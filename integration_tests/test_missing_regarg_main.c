#include <stdio.h>

int regarg_caller(int value);

int main(void)
{
    int value = regarg_caller(5);
    printf("%d\n", value);
    return value == 12 ? 0 : 1;
}
