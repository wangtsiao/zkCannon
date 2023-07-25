use super::*;

pub enum Lookup<F> {
    /// Lookup to fixed table, which contains serveral pre-built tables such as
    /// range tables or bitwise tables.
    Fixed {
        tag: Expression<F>,
        values: [Expression<F>; 3],
    },
    /// Lookup to read-write table, which contains read-write access records of
    /// time-aware data.
    Rw {
        /// Counter for how much read-write have been done, which stands for
        /// the sequential timestamp.
        counter: Expression<F>,
        /// A boolean value to specify if the access record is a read or write.
        is_write: Expression<F>,
        /// Tag to specify which read-write data to access, see RwTableTag for
        /// all tags.
        tag: Expression<F>,
        /// Values corresponding to the tag.
        address: Expression<F>,
        value: Expression<F>,
    },
    /// Lookup to bytecode table, which contains all used creation code and
    /// contract code.
    Opcode {
        /// Tag to specify whether its the bytecode length or byte value in the
        /// bytecode.
        tag: Expression<F>,
        /// Index to specify which byte of bytecode.
        index: Expression<F>,
        /// Value corresponding to the tag.
        value: Expression<F>,
    },
}

impl<F: Field> Lookup<F> {
    pub fn table(&self) -> Table {
        match self {
            Self::Fixed { .. } => Table::Fixed,
            Self::Rw { .. } => Table::Rw,
            Self::Opcode { .. } => Table::Opcode,
        }
    }

    pub fn input_exprs(&self) -> Vec<Expression<F>> {
        match self {
            Self::Fixed { tag, values} => [vec![tag.clone()], values.to_vec()].concat(),
            Self::Rw {
                counter,
                is_write,
                tag,
                address,
                value,
            } => vec![
                counter.clone(),
                is_write.clone(),
                tag.clone(),
                address.clone(),
                value.clone(),
            ],
            Self::Opcode {
                tag,
                index,
                value,
            } => vec![
                tag.clone(),
                index.clone(),
                value.clone(),
            ],
        }
    }
}
