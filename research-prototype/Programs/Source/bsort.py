from Compiler import types, library, instructions


def new_dest_comp(B):
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

    @library.for_range(len(St_flat) - 1)
    def _(i):
        St_flat[i + 1] = St_flat[i + 1] + St_flat[i]

    cumval = St_flat.get_vector(size=num)
    cumshift = St_flat.get_vector(base=num, size=num) - cumval
    dest = cumval + Bt_flat.get_vector(base=num, size=num) * cumshift - 1
    Tt = types.Array(num, B.value_type)
    Tt.assign_vector(dest)
    return Tt


def reveal_sort(k, D, reverse=False):
    assert len(k) == len(D)
    library.break_point()
    shuffle = types.sint.get_secure_shuffle(len(k))
    k_prime = k.get_vector().secure_permute(shuffle).reveal()
    idx = types.Array.create_from(k_prime)
    if reverse:
        D.assign_vector(D.get_slice_vector(idx))
        library.break_point()
        D.secure_permute(shuffle, reverse=True)
    else:
        D.secure_permute(shuffle)
        library.break_point()
        v = D.get_vector()
        D.assign_slice_vector(idx, v)
    library.break_point()
    instructions.delshuffle(shuffle)


def bit_radix_sort(bst, D):
    """
    bs: a N by B bit array
    D: a N long array to be permuted.
    """
    num, n_bits = bst.sizes
    assert num == len(D)
    B = types.sint.Matrix(num, 2)
    h = types.Array.create_from(types.sint(types.regint.inc(num)))
    bs = bst.transpose()

    @library.for_range(num)
    def _(i):
        b = bs[i]
        B.set_column(0, 1 - b.get_vector())
        B.set_column(1, b.get_vector())
        c = types.Array.create_from(new_dest_comp(B))
        reveal_sort(c, h, reverse=False)

        @library.if_e(i < num - 1)
        def _():
            reveal_sort(h, bs[i + 1], reverse=True)

        @library.else_
        def _():
            reveal_sort(h, D, reverse=True)


def new_radix_sort(k, D, n_bits=None, signed=True):
    bs = types.Matrix.create_from(k.get_vector().bit_decompose(n_bits))
    if signed and len(bs) > 1:
        bs[-1][:] = bs[-1][:].bit_not()
    bit_radix_sort(bs.transpose(), D)
