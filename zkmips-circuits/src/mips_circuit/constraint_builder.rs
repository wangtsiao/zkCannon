use super::*;

#[derive(Clone, Debug)]
pub struct Step<F> {
    // Program Counter, also known as Address
    pub pc_register: Cell<F>,
    // Read Write Counter
    pub rw_counter: Cell<F>,
    // Bytecode, which is a 32 bits unsigned value
    pub bytecode: Cell<F>,
    // All 32 MIPS Registers
    pub registers: [Cell<F>; 32],
    // Hi Register, used to Multiply
    pub hi: Cell<F>,
    // Lo Register, used to Multiply
    pub lo: Cell<F>,
    // Cell Manager, to fetch halo2 column
    pub cell_manager: CellManager<CMFixedWidthStrategy>,
}

#[derive(Clone, Debug)]
pub struct StoredExpression<F> {
    pub name: String,
    pub cell: Cell<F>,
    pub cell_type: CellType,
    pub expr: Expression<F>,
    pub expr_id: String,
}


pub struct MIPSConstraintBuilder<'a, F: Field> {
    pub curr: Step<F>,
    pub next: Step<F>,
    pub constraints: Vec<(&'static str, Expression<F>)>,
    pub conditions: Vec<Expression<F>>,
    pub max_degree: usize,
    pub meta: &'a mut ConstraintSystem<F>,
    pub in_next_step: bool,
    pub stored_expressions: Vec<StoredExpression<F>>,
    pub challenges: &'a Challenges<Expression<F>>,
}


impl<'a, F: Field> MIPSConstraintBuilder<'a, F> {
    pub fn new(
        meta: &'a mut ConstraintSystem<F>,
        curr: Step<F>,
        next: Step<F>,
        challenges: &'a Challenges<Expression<F>>,
        max_degree: usize,
    ) -> Self {
        Self {
            curr,
            next,
            constraints: vec![],
            conditions: vec![],
            max_degree,
            meta,
            in_next_step: false,
            stored_expressions: vec![],
            challenges,
        }
    }

    /// Check whether the given degree is larger than `max_degree`
    pub fn validate_degree(&self, degree: usize, name: &'static str) {
        if self.max_degree > 0 {
            debug_assert!(
                degree <= self.max_degree,
                "Expression {} degree too high {} > {}",
                name,
                degree,
                self.max_degree
            );
        }
    }

    /// Return new constraints with the given selector
    pub fn gate(&self, selector: Expression<F>) -> Vec<(&'static str, Expression<F>)> {
        self.constraints
            .clone()
            .into_iter()
            .map(|(name, constraint)| (name, selector.clone() * constraint))
            .filter(|(name, constraint)| {
                self.validate_degree(constraint.degree(), name);
                true
            })
            .collect()
    }

    /// Insert the given constraint
    pub fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.validate_degree(constraint.degree(), name);
        self.constraints.push((name, constraint));
    }

    /// Places, and returns `count` Cells for a given cell type following the fixed width strategy
    pub fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>>{
        if self.in_next_step {
            &mut self.next
        } else {
            &mut self.curr
        }
            .cell_manager
            .query_cells(self.meta, cell_type, count)
    }

    /// Places, and return a Storage Cell following the fixed width strategy
    pub fn query_cell(&mut self) -> Cell<F> {
        self.query_cells(CellType::Storage, 1).first().unwrap().clone()
    }

    pub fn query_u8_dyn(&mut self, count: usize) -> Vec<Cell<F>> {
        self.query_cells(CellType::Lookup(Table::U8), count)
    }

    pub fn query_bytes<const N: usize>(&mut self) -> [Cell<F>; N] {
        self.query_u8_dyn(N).try_into().unwrap()
    }

    /// todo: implement query word32, for register, immediate number, and address

    pub fn require_equal(&mut self, name: &'static str, lhs: Expression<F>, rhs: Expression<F>) {
        self.add_constraint(name, lhs - rhs);
    }

    pub fn require_boolean(&mut self, name: &'static str, value: Expression<F>) {
        self.add_constraint(name, value.clone() * (1.expr() - value));
    }

    pub fn require_zero(&mut self, name: &'static str, constraint: Expression<F>) {
        self.add_constraint(name, constraint);
    }

    pub fn require_true(&mut self, name: &'static str, value: Expression<F>) {
        self.require_equal(name, value, 1.expr());
    }

    pub fn add_constraints(&mut self, constraints: Vec<(&'static str, Expression<F>)>) {
        for (name, constraint) in constraints {
            self.add_constraint(name, constraint);
        }
    }

    pub fn add_lookup(&mut self, name: &str, lookup: Lookup<F>) {
        let compressed_expr = self.split_expression(
            "Lookup compression",
            rlc::expr(&lookup.input_exprs(), self.challenges.lookup_input()),
            self.max_degree,
        );
        self.store_expression(name, compressed_expr, CellType::Lookup(lookup.table()));
    }

    fn find_stored_expression(
        &self,
        expr: &Expression<F>,
        cell_type: CellType,
    ) -> Option<&StoredExpression<F>> {
        let expr_id = expr.identifier();
        self.stored_expressions
            .iter()
            .find(|&e| e.cell_type == cell_type && e.expr_id == expr_id)
    }

    fn store_expression(
        &mut self,
        name: &str,
        expr: Expression<F>,
        cell_type: CellType,
    ) -> Expression<F> {
        // Check if we already stored the expression somewhere
        let stored_expression = self.find_stored_expression(&expr, cell_type);

        match stored_expression {
            Some(stored_expression) => {
                debug_assert!(
                    !matches!(cell_type, CellType::Lookup(_)),
                    "The same lookup is done multiple times",
                );
                stored_expression.cell.expr()
            }
            None => {
                // Even if we're building expressions for the next step,
                // these intermediate values need to be stored in the current step.
                let in_next_step = self.in_next_step;
                self.in_next_step = false;
                let cell = self.query_cells(cell_type, 1).first().unwrap().clone();
                self.in_next_step = in_next_step;

                // Require the stored value to equal the value of the expression
                let name = format!("{} (stored expression)", name);
                self.constraints.push(
                    (Box::leak(name.clone().into_boxed_str()), cell.expr() - expr.clone())
                );

                self.stored_expressions.push(StoredExpression {
                    name: name.clone(),
                    cell: cell.clone(),
                    cell_type,
                    expr_id: expr.identifier(),
                    expr,
                });
                cell.expr()
            }
        }
    }

    fn split_expression(
        &mut self,
        name: &'static str,
        expr: Expression<F>,
        max_degree: usize,
    ) -> Expression<F> {
        if expr.degree() > max_degree {
            match expr {
                Expression::Negated(poly) => {
                    Expression::Negated(Box::new(self.split_expression(name, *poly, max_degree)))
                }
                Expression::Scaled(poly, v) => {
                    Expression::Scaled(Box::new(self.split_expression(name, *poly, max_degree)), v)
                }
                Expression::Sum(a, b) => {
                    let a = self.split_expression(name, *a, max_degree);
                    let b = self.split_expression(name, *b, max_degree);
                    a + b
                }
                Expression::Product(a, b) => {
                    let (mut a, mut b) = (*a, *b);
                    while a.degree() + b.degree() > max_degree {
                        let mut split = |expr: Expression<F>| {
                            if expr.degree() > max_degree {
                                self.split_expression(name, expr, max_degree)
                            } else {
                                self.store_expression(name, expr, CellType::Storage)
                            }
                        };
                        if a.degree() >= b.degree() {
                            a = split(a);
                        } else {
                            b = split(b);
                        }
                    }
                    a * b
                }
                _ => expr.clone(),
            }
        } else {
            expr.clone()
        }
    }
}
