// Copyright 2020 Proyectos y Sistemas de Mantenimiento SL (eProsima).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>

#define FLAGS_LEN	16

static bool * get_memory_lock(void *addr)
{
  static bool memory_locks[FLAGS_LEN] = { 0 };

  // Implement here a randomization function based on addr

  return memory_locks;
}

void lock_memory(uint64_t *mem){
  bool * memory_lock = get_memory_lock(mem);

  while (__atomic_test_and_set(memory_lock, __ATOMIC_ACQUIRE) == 1);
}

void unlock_memory(uint64_t *mem){
  bool * memory_lock = get_memory_lock(mem);

  __atomic_clear(memory_lock, __ATOMIC_RELEASE);
}

uint64_t __atomic_load_8(uint64_t *mem, int model) { 
  (void) model;

  lock_memory(mem); 
  uint64_t ret = *mem; 
  unlock_memory(mem); 
  return ret; 
}

void __atomic_store_8(uint64_t *mem, uint64_t val, int model) { 
  (void) model;

  lock_memory(mem); 
  *mem = val; 
  unlock_memory(mem); 
}

uint64_t __atomic_exchange_8(uint64_t *mem, uint64_t val, int model) { 
  (void) model;

  lock_memory(mem); 
  uint64_t ret = *mem; 
  *mem = val; 
  unlock_memory(mem); 
  return ret; 
}

uint64_t __atomic_fetch_add_8(uint64_t *mem, uint64_t val, int model) { 
  (void) model;

  lock_memory(mem); 
  uint64_t ret = *mem; 
  *mem += val; 
  unlock_memory(mem); 
  return ret; 
}

#ifdef __cplusplus
}
#endif
