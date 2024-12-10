use plonky2::{
    field::{extension::Extendable, packed::PackedField, types::Field},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

pub(crate) const ROUND_FLAGS_LEN: usize = 5;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RoundFlags<T: Copy + Clone + Default> {
    pub(crate) is_first_round: T,    // 1 if counter == 0, 0 otherwise
    pub(crate) is_last_round: T,     // 1 if counter == period - 1, 0 otherwise
    pub(crate) counter: T,           // count from 0 to period - 1, periodically
    pub(crate) inv_counter: T,       // counter.inverse() if counter != 0, 0 otherwise
    pub(crate) inv_counter_prime: T, // same as above, but for counter_prime = counter - period + 1
}

pub(crate) fn generate_round_flags<F: RichField>(row_index: usize, period: usize) -> RoundFlags<F> {
    let counter = F::from_canonical_usize(row_index % period);
    let counter_prime = counter - F::from_canonical_usize(period - 1);

    let is_first_round = F::from_bool(counter.is_zero());
    let is_last_round = F::from_bool(counter_prime.is_zero());
    let inv_counter = if counter.is_zero() {
        F::ZERO
    } else {
        counter.inverse()
    };
    let inv_counter_prime = if counter_prime.is_zero() {
        F::ZERO
    } else {
        counter_prime.inverse()
    };
    RoundFlags {
        is_first_round,
        is_last_round,
        counter,
        inv_counter,
        inv_counter_prime,
    }
}

pub(crate) fn eval_round_flags<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    period: usize,
    filter: P,
    round_flags: RoundFlags<P>,
    next_counter: P,
) {
    // is_first_round = 0 if filter = 0
    let not_filter = P::ONES - filter;
    yield_constr.constraint(not_filter * round_flags.is_first_round);
    // is_last_round = 0 if filter = 0
    yield_constr.constraint(not_filter * round_flags.is_last_round);

    // counter * first_round_aux = 1 - is_first_round
    let is_first_round_minus_one = P::ONES - round_flags.is_first_round;
    yield_constr.constraint(
        filter * (round_flags.counter * round_flags.inv_counter - is_first_round_minus_one),
    );
    // counter * is_first_round = 0
    yield_constr.constraint(filter * round_flags.counter * round_flags.is_first_round);
    let counter_prime = round_flags.counter - P::Scalar::from_canonical_usize(period - 1);
    // counter_prime * last_round_aux = 1 - is_last_round
    let is_last_round_minus_one = P::ONES - round_flags.is_last_round;
    yield_constr.constraint(
        filter * (counter_prime * round_flags.inv_counter_prime - is_last_round_minus_one),
    );
    // counter_prime * is_last_round = 0
    yield_constr.constraint(filter * counter_prime * round_flags.is_last_round);

    // next_counter = counter + 1 if !is_last_round
    let is_not_last_round = P::ONES - round_flags.is_last_round;
    yield_constr
        .constraint(filter * is_not_last_round * (next_counter - round_flags.counter - P::ONES));
    // next_counter = 0 if is_last_round
    yield_constr.constraint(filter * round_flags.is_last_round * next_counter);
}

pub(crate) fn eval_round_flags_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    period: usize,
    filter: ExtensionTarget<D>,
    round_flags: RoundFlags<ExtensionTarget<D>>,
    next_counter: ExtensionTarget<D>,
) {
    let one = builder.constant_extension(F::Extension::ONE);

    // is_first_round = 0 if filter = 0
    let not_fitler = builder.sub_extension(one, filter);
    let first_round_not_filter = builder.mul_extension(not_fitler, round_flags.is_first_round);
    yield_constr.constraint(builder, first_round_not_filter);

    // is_last_round = 0 if filter = 0
    let last_round_not_filter = builder.mul_extension(not_fitler, round_flags.is_last_round);
    yield_constr.constraint(builder, last_round_not_filter);

    // counter * first_round_aux = 1 - is_first_round
    let is_first_round_minus_one = builder.sub_extension(one, round_flags.is_first_round);
    let t = builder.mul_sub_extension(
        round_flags.counter,
        round_flags.inv_counter,
        is_first_round_minus_one,
    );
    let t_filtered = builder.mul_extension(filter, t);
    yield_constr.constraint(builder, t_filtered);

    // counter * is_first_round = 0
    let t = builder.mul_extension(round_flags.counter, round_flags.is_first_round);
    let t_filtered = builder.mul_extension(filter, t);
    yield_constr.constraint(builder, t_filtered);
    // let counter_prime = round_flags.counter -
    // P::Scalar::from_canonical_usize(period - 1);
    let period_minus_one =
        builder.constant_extension(F::Extension::from_canonical_usize(period - 1));
    let counter_prime = builder.sub_extension(round_flags.counter, period_minus_one);

    // counter_prime * last_round_aux = 1 - is_last_round
    let is_last_round_minus_one = builder.sub_extension(one, round_flags.is_last_round);
    let t = builder.mul_sub_extension(
        counter_prime,
        round_flags.inv_counter_prime,
        is_last_round_minus_one,
    );
    let t_filtered = builder.mul_extension(filter, t);
    yield_constr.constraint(builder, t_filtered);
    // counter_prime * is_last_round = 0
    let t = builder.mul_extension(counter_prime, round_flags.is_last_round);
    let t_filtered = builder.mul_extension(filter, t);
    yield_constr.constraint(builder, t_filtered);

    // next_counter = counter + 1 if !is_last_round
    let is_not_last_round = builder.sub_extension(one, round_flags.is_last_round);
    let counter_plus_one = builder.add_extension(round_flags.counter, one);
    let diff = builder.sub_extension(next_counter, counter_plus_one);
    let t = builder.mul_extension(is_not_last_round, diff);
    let t_filtered = builder.mul_extension(filter, t);
    yield_constr.constraint(builder, t_filtered);
    // next_counter = 0 if is_last_round
    let t = builder.mul_extension(round_flags.is_last_round, next_counter);
    let t_filtered = builder.mul_extension(filter, t);
    yield_constr.constraint(builder, t_filtered);
}
