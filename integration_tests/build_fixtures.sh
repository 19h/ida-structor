#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cc=${CC:-clang}
cxx=${CXX:-clang++}
cflags="-g -O0"
cxxflags="-g -O0 -std=c++17"
opt_cflags="-g -O2"

build_c() {
    src="$1"
    out="${src%.c}"
    "$cc" $cflags -o "$out" "$src"
}

build_optimized_c() {
    src="$1"
    out="${src%.c}"
    "$cc" $opt_cflags -o "$out" "$src"
}

build_cxx() {
    src="$1"
    out="${src%.cpp}"
    "$cxx" $cxxflags -o "$out" "$src"
}

build_missing_regarg() {
    arch=$(uname -m)
    if [ "$arch" != "arm64" ] && [ "$arch" != "aarch64" ]; then
        return
    fi

    asm_src="$root/test_missing_regarg_arm64.S"
    main_src="$root/test_missing_regarg_main.c"
    obj="$root/test_missing_regarg_arm64.o"
    out="$root/test_missing_regarg"

    "$cc" $cflags -c "$asm_src" -o "$obj"
    "$cc" $cflags -o "$out" "$main_src" "$obj"
}

build_named() {
    name="$1"

    case "$name" in
        missing_regarg|test_missing_regarg)
            build_missing_regarg
            ;;
        overlap_scope|test_overlap_scope)
            build_optimized_c "$root/test_overlap_scope.c"
            ;;
        *)
            if [ -f "$root/$name.c" ]; then
                build_c "$root/$name.c"
            elif [ -f "$root/$name.cpp" ]; then
                build_cxx "$root/$name.cpp"
            else
                printf 'Unknown fixture: %s\n' "$name" >&2
                exit 1
            fi
            ;;
    esac
}

if [ "$#" -gt 0 ]; then
    for name in "$@"; do
        build_named "$name"
    done
    exit 0
fi

build_c "$root/test_simple_struct.c"
build_c "$root/test_function_ptr.c"
build_c "$root/test_linked_list.c"
build_c "$root/test_mixed_access.c"
build_c "$root/test_nested.c"
build_c "$root/test_nested_2d.c"
build_c "$root/test_substructure.c"
build_c "$root/test_callgraph_return.c"
build_c "$root/test_cross_conflict_union.c"
build_c "$root/test_packed_struct.c"
build_c "$root/test_packed_nested_array.c"
build_c "$root/test_packed_union_overlap.c"
build_c "$root/test_negative_offsets.c"
build_c "$root/test_array_of_structs.c"
build_c "$root/test_array_of_structs_nested.c"
build_c "$root/test_bounded_index.c"
build_c "$root/test_enum_constants.c"
build_c "$root/test_flags_union.c"
build_c "$root/test_callback_table.c"
build_c "$root/test_indirect_shifted_call.c"
build_c "$root/test_local_alias_positive.c"
build_c "$root/test_mixed_subobject_deltas.c"
build_c "$root/test_shifted_siblings.c"
build_c "$root/test_tree_struct.c"
build_c "$root/test_partial_overlap.c"
build_optimized_c "$root/test_overlap_scope.c"
build_c "$root/test_vtable_direct.c"
build_missing_regarg
build_cxx "$root/test_vtable.cpp"
build_cxx "$root/test_vtable_positive.cpp"
