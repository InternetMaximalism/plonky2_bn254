use crate::starks::{
    curves::g2::{scalar_mul_view::INPUT_FILTER_COL, G2},
    LIMB_BITS, U256,
};

use super::{
    scalar_mul_stark::G2ScalarMulInput,
    scalar_mul_view::{A_COLS, BITS_COLS, B_COLS, OUTPUT_FILTER_COL, SUM_COLS, TIMESTAMP_COL},
};
use ark_bn254::G2Affine;
use ark_ec::AffineRepr;
use hashbrown::HashMap;
use itertools::Itertools;
use plonky2::{field::types::Field, hash::hash_types::RichField};
use starky::{
    cross_table_lookup::{CrossTableLookup, TableWithColumns},
    lookup::{Column, Filter},
};

pub(crate) fn scalar_mul_ctl<F: Field>() -> Vec<CrossTableLookup<F>> {
    let x_limb_cols = Column::singles(B_COLS);
    let offset_limb_cols = Column::singles(A_COLS);
    let s_limb_cols = BITS_COLS
        .chunks(LIMB_BITS)
        .into_iter()
        .map(|chunk| Column::le_bits(chunk))
        .collect::<Vec<_>>();
    let output_limb_cols = Column::singles(SUM_COLS);
    let timestamp_col = Column::single(TIMESTAMP_COL);

    let mut input_cols = vec![];
    input_cols.extend(x_limb_cols);
    input_cols.extend(offset_limb_cols);
    input_cols.extend(s_limb_cols);
    input_cols.push(timestamp_col.clone());
    let input_looked_table = TableWithColumns::new(
        0,
        input_cols,
        Filter::new_simple(Column::single(INPUT_FILTER_COL)),
    );

    let mut output_cols = vec![];
    output_cols.extend(output_limb_cols);
    output_cols.push(timestamp_col);
    let output_looked_table = TableWithColumns::new(
        0,
        output_cols,
        Filter::new_simple(Column::single(OUTPUT_FILTER_COL)),
    );

    vec![
        CrossTableLookup::new(vec![], input_looked_table),
        CrossTableLookup::new(vec![], output_looked_table),
    ]
}

pub(crate) fn generate_ctl_values<F: RichField>(
    inputs: &[G2ScalarMulInput],
) -> HashMap<usize, Vec<Vec<F>>> {
    let mut e = HashMap::new();
    let mut inputs_ctl = vec![];
    let mut outputs_ctl = vec![];
    for input in inputs {
        let mut input_ctl = vec![];
        input_ctl.extend_from_slice(G2::from(input.x).to_slice());
        input_ctl.extend_from_slice(G2::from(input.offset).to_slice());
        input_ctl.extend_from_slice(U256::from(input.s.clone()).to_slice());
        input_ctl.push(F::from_canonical_usize(input.timestamp));
        let mut output_ctl = vec![];
        let output: G2Affine = (input.x.mul_bigint(input.s.to_u64_digits()) + input.offset).into();
        output_ctl.extend_from_slice(G2::from(output).to_slice());
        output_ctl.push(F::from_canonical_usize(input.timestamp));

        inputs_ctl.push(input_ctl);
        outputs_ctl.push(output_ctl);
    }
    e.insert(0, inputs_ctl);
    e.insert(1, outputs_ctl);
    e
}
