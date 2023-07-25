use super::*;

#[derive(Clone, Debug, Default)]
pub struct CMFixedWidthStrategyDistribution(HashMap<CellType, Vec<Column<Advice>>>);

impl CMFixedWidthStrategyDistribution {
    pub(crate) fn add(&mut self, cell_type: CellType, advice: Column<Advice>) {
        if let Some(v) = self.0.get_mut(&cell_type) {
            v.push(advice);
        } else {
            self.0.insert(cell_type, vec![advice]);
        }
    }

    pub(crate) fn get(&self, cell_type: CellType) -> Option<&Vec<Column<Advice>>> {
        self.0.get(&cell_type)
    }
}

/// CMFixedWidthStrategy is a Cell Manager strategy that places the cells in the column that has
/// less height for a given CellType.
/// When a cell is queried for a CellType the strategy will find the column of that Cell Type that
/// has a lower height and add it there.
#[derive(Clone, Debug)]
pub struct CMFixedWidthStrategy {
    advices: CMFixedWidthStrategyDistribution,
    height_offset: usize,

    next: HashMap<CellType, (usize, usize)>,

    max_height: usize,
}

impl CMFixedWidthStrategy {
    /// Creates a CMFixedWidthStrategy from a CMFixedWidthStrategyDistribution that contains advice
    /// columns categorized by Cell Type.
    /// The argument height_offset will be added to the rotation of the Cells, which is useful for a
    /// next step.
    pub fn new(
        advices: CMFixedWidthStrategyDistribution,
        height_offset: usize,
    ) -> CMFixedWidthStrategy {
        CMFixedWidthStrategy {
            advices,
            height_offset,
            next: HashMap::default(),
            max_height: usize::max_value(),
        }
    }

    /// Sets a max height, if the strategy chooses a height that is over this, it will panic.
    pub fn with_max_height(mut self, max_height: usize) -> Self {
        self.max_height = max_height;

        self
    }

    fn get_next(&self, cell_type: &CellType) -> (usize, usize) {
        *self.next.get(cell_type).unwrap_or(&(0, 0))
    }

    fn set_next(&mut self, cell_type: &CellType, column_idx: usize, row: usize) {
        self.next.insert(*cell_type, (column_idx, row));
    }

    fn cells_used(&self, cell_type: &CellType, columns: &CellManagerColumns) -> usize {
        let (next_column_idx, next_row) = self.get_next(cell_type);
        let current_row = if next_column_idx == 0 {
            if next_row == 0 {
                return 0;
            }

            next_row - 1
        } else {
            next_row
        };

        let filled_rows_cells = if current_row == 0 {
            0
        } else {
            (current_row - 1) * columns.get_cell_type_width(*cell_type)
        };

        filled_rows_cells + next_column_idx
    }
}

impl CellManagerStrategy for CMFixedWidthStrategy {
    type Stats = BTreeMap<CellType, (usize, usize, usize)>;

    fn on_creation(&mut self, columns: &mut CellManagerColumns) {
        for (cell_type, advices) in self.advices.0.iter() {
            for column in advices.iter() {
                columns.add_column(*cell_type, *column)
            }
        }
    }

    fn query_cell<F: Field>(
        &mut self,
        columns: &mut CellManagerColumns,
        meta: &mut ConstraintSystem<F>,
        cell_type: CellType,
    ) -> Cell<F> {
        let (mut column_idx, mut row) = self.get_next(&cell_type);

        if row > self.max_height {
            panic!(
                "CMFixedWidthStrategy: max_height reached ({})",
                self.max_height
            )
        }

        let column = columns
            .get_column(cell_type, column_idx)
            .expect("column not found");

        let cell = Cell::new_from_cs(meta, column.advice, column.idx, self.height_offset + row);

        column_idx += 1;
        if column_idx >= columns.get_cell_type_width(cell_type) {
            column_idx = 0;
            row += 1;
        }

        self.set_next(&cell_type, column_idx, row);

        cell
    }

    fn get_height(&self) -> usize {
        self.next
            .keys()
            .map(|cell_type| {
                let next = self.get_next(cell_type);
                if next.0 == 0 {
                    next.1
                } else {
                    next.1 + 1
                }
            })
            .max()
            .unwrap_or(0)
    }

    fn get_stats(&self, columns: &CellManagerColumns) -> Self::Stats {
        let mut data = BTreeMap::new();
        for cell_type in self.next.keys() {
            let next = self.get_next(cell_type);
            let height = if next.0 == 0 { next.1 } else { next.1 + 1 };
            data.insert(
                *cell_type,
                (
                    columns.get_cell_type_width(*cell_type),
                    height,
                    self.cells_used(cell_type, columns),
                ),
            );
        }
        data
    }
}
