#
# Copyright (C) 2016 https://www.brobwind.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

all: bro_aes

STANDARD_AS_OPENSSL ?= 0

CFLAGS := -DSTANDARD_AS_OPENSSL=$(strip $(STANDARD_AS_OPENSSL))

OBJS := main.o bro_aes.o bro_util.o

bro_aes: $(OBJS)
	gcc -o $@ $^

clean:
	@-rm $(OBJS) bro_aes

.PHONY: clean
