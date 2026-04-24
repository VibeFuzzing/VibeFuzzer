#include <stdio.h>
#include "../mutator/mutator.c"

int main() {
    llm_mutator_t data = {0};
    data.i = 0;
    
    for (int iter = 0; iter < 210; iter++) {
        data.i = (data.i + 1) % 200;
        printf("Iter %d: data.i = %d, will_call_api = %d\n", iter, data.i, (data.i == 0) ? 1 : 0);
    }
    
    return 0;
}
