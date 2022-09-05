from Compiler.instructions import delshuffle
from Compiler.library import for_range, break_point, if_, else_, if_e
from Compiler.types import Array, Matrix, sint, regint
from Compiler.sorting import radix_sort as mp_spdz_radix_sort


def dest_comp(B):
    """
    Compute the 'destination' permutation

    Calculate the permutation to stable sort a bit vector.
    In the original, we multiply have of the cumulative sums
    by the bits, and half by the complements of the bits.
    This can be improved by just refactoring:
    dest[i] = (1 - keys[i]) * cumval[i] + keys[i] * cumval[i + n]
    = cumval[i] + keys[i] * (cumval[i + n] - cumval[i])
    Note: this gives the destination for 1-origin indexing
    for 0-origin (as in Python) we must subtract 1.
    """
    Bt = B.transpose()
    Bt_flat = Bt.get_vector()
    St_flat = Bt.value_type.Array(len(Bt_flat))
    St_flat.assign(Bt_flat)
    num = len(St_flat) // 2

    @for_range(len(St_flat) - 1)
    def _(i):
        St_flat[i + 1] = St_flat[i + 1] + St_flat[i]

    cumval = St_flat.get_vector(size=num)
    cumshift = St_flat.get_vector(base=num, size=num) - cumval
    dest = cumval + Bt_flat.get_vector(base=num, size=num) * cumshift - 1
    Tt = Array(num, B.value_type)
    Tt.assign_vector(dest)
    return Tt


def reveal_sort(k, D, reverse=False):
    """
    k is a permutation.
    Rearrange D by k.
    """
    assert len(k) == len(D)
    break_point()
    shuffle = sint.get_secure_shuffle(len(k))
    k_prime = k.get_vector().secure_permute(shuffle).reveal()
    idx = Array.create_from(k_prime)
    if D:
        reverse.assign_vector(D.get_slice_vector(idx))
        break_point()
        D.secure_permute(shuffle, reverse=True)
    else:
        D.secure_permute(shuffle)
        break_point()
        v = D.get_vector()
        D.assign_slice_vector(idx, v)
    break_point()
    delshuffle(shuffle)


def double_dest(bs):
    """
    bs is an n by 2 bit array.
    """
    num, _ = bs.sizes
    bits = sint.Array(num * 4)
    col0 = bs.get_column(0)
    col1 = bs.get_column(1)
    prod = col0 * col1
    bits.assign_vector(prod - col0 - col1 + 1)  # 00
    bits.assign_vector(col1 - prod, base=num)  # 01
    bits.assign_vector(col0 - prod, base=2 * num)  # 10
    bits.assign_vector(prod, base=3 * num)  # 11

    @for_range(num - 1)
    def _(i):
        bits[i + 1] = bits[i + 1] + bits[i]

    one_contrib = bits.get_vector(size=num)
    col0_contrib = bits.get_vector(base=2 * num, size=num) - one_contrib
    col1_contrib = bits.get_vector(base=num, size=num) - one_contrib
    prod_contrib = one_contrib + bits.get_vector(base=3 * num, size=num)
    return (
        one_contrib
        + col0 * col0_contrib
        + col1 * col1_contrib
        + prod * prod_contrib
        - 1
    )


def double_bit_radix_sort(bs, D):
    """
    Use two bits at a time.
    There's an annoying problem if n_bits is odd.
    """
    n_bits, num = bs.sizes
    h = Array.create_from(sint(regint.inc(num)))

    # Test if n_bits is odd
    @for_range(n_bits // 2)
    def _(i):
        perm = double_dest(bs[2 * i : 2 * i + 2])
        reveal_sort(perm, h, reverse=False)

        @if_e(2 * i + 3 < n_bits)
        def _():  # sort the next 2 bits
            reveal_sort(h, bs[2 * i + 2 : 2 * i + 4], reverse=True)

        @else_
        def _():
            @if_(n_bits % 2 == 1)
            def odd_case():
                reveal_sort(h, bs[-1], reverse=True)
                c = Array.create_from(dest_comp(bs[-1]))
                reveal_sort(c, h, reverse=False)

    # Now take care of the odd case
    reveal_sort(h, D, reverse=True)


def bit_radix_sort(bs, D):
    n_bits, num = bs.sizes
    B = sint.Matrix(num, 2)
    h = Array.create_from(sint(regint.inc(num)))

    @for_range(n_bits)
    def _(i):
        b = bs[i]
        B.set_column(0, 1 - b.get_vector())
        B.set_column(1, b.get_vector())
        c = Array.create_from(dest_comp(B))
        reveal_sort(c, h, reverse=False)

        @if_e(i < n_bits - 1)
        def _():
            reveal_sort(h, bs[i + 1], reverse=True)

        @else_
        def _():
            reveal_sort(h, D, reverse=True)


def radix_sort(k, D, n_bits=None, signed=True, two_bit=False):
    assert len(k) == len(D)
    bs = Matrix.create_from(k.get_vector().bit_decompose(n_bits))
    if signed and len(bs) > 1:
        bs[-1][:] = bs[-1][:].bit_not()
    if two_bit:
        double_bit_radix_sort(bs, D)
    else:
        bit_radix_sort(bs, D)


def two_bit_radix_sort(k, D, n_bits):
    return radix_sort(k, D, n_bits, two_bit=True)


def batcher_sort(k, D, n_bits):
    raise NotImplementedError("Batcher not implemented")


sort_functions = {
    "LIBRARY_SORT": mp_spdz_radix_sort,
    "RADIX_SORT": radix_sort,
    "TWO_BIT_RADIX_SORT": two_bit_radix_sort,
    "BATCHER_SORT": batcher_sort,
}
