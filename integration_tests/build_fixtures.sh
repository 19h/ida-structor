#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cc=${CC:-clang}
cxx=${CXX:-clang++}
cflags="-g -O0"
cxxflags="-g -O0 -std=c++17"

build_c() {
    src="$1"
    out="${src%.c}"
    "$cc" $cflags -o "$out" "$src"
}

build_cxx() {
    src="$1"
    out="${src%.cpp}"
    "$cxx" $cxxflags -o "$out" "$src"
}

build_c "$root/test_simple_struct.c"
build_c "$root/test_function_ptr.c"
build_c "$root/test_linked_list.c"
build_c "$root/test_mixed_access.c"
build_c "$root/test_nested.c"
build_c "$root/test_substructure.c"
build_c "$root/test_callgraph_return.c"
build_c "$root/test_packed_struct.c"
build_c "$root/test_negative_offsets.c"
build_c "$root/test_array_of_structs.c"
build_c "$root/test_flags_union.c"
build_c "$root/test_vtable_direct.c"
build_cxx "$root/test_vtable.cpp"
build_cxx "$root/test_vtable_positive.cpp"
