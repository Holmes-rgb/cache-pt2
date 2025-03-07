# Luke Holmes and Greta Schutz

from enum import Enum

WORDLENGTH       = 4

# some specific values
MEMORY_SIZE      = 65536 # 2^16
CACHE_SIZE       = 1024  # 2^10
CACHE_BLOCK_SIZE = 64    # 2^6
ASSOCIATIVITY    = 4     # direct mapped
WRITE_BACK       = 0

NUM_SETS = (CACHE_SIZE // (CACHE_BLOCK_SIZE * ASSOCIATIVITY))
NUM_BLOCKS = (CACHE_SIZE // CACHE_BLOCK_SIZE)

# a few globals, will be set later
memory_size_bits = 0
cache = None
memory = bytearray(MEMORY_SIZE)

# examples of tag, index, offset; with block size = 64 (6 bits)
# and address length = 16 bits
# if there are 8 sets:
# index is 3 bits: 1024 / (8*64); it's the set number
# blockIndex will be the first block in the set
# block offset is 6 bits
# so tag is 16 - 3 - 6 = 7 bits
#
# if there are 4 sets:
# index is 2 bits: 1024 / (4*64); it's the set number
# blockIndex will be the first block in the set
# block offset is 6 bits
# so tag is 16 - 2 - 6 = 8 bits

#======================================================================
# for part one, we need only reads

class AccessType(Enum):
    READ = 0
    WRITE = 1

#======================================================================

class CacheBlock:
    def __init__(self, cache_block_size):
        self.tag = -1
        self.dirty = False
        self.valid = False
        self.data = bytearray(cache_block_size)

#======================================================================
# strictly speaking, don't need a tag queue for part one

class CacheSet:
    def __init__(self, cache_block_size, associativity):
        self.blocks = [CacheBlock(cache_block_size) for i in range(associativity)]
        # for part one, each set has one block, and so we need to
        # save only a single tag value for a set
        self.tag = -1

        # for part two, you'll need a tag queue, like this:
        self.tag_queue = [-1 for i in range(associativity)]

#======================================================================

class Cache:
    def __init__(self, num_sets, associativity, cache_block_size):
        self.write_through = False
        self.sets = [CacheSet(cache_block_size, associativity) for i in range(num_sets)]
        global memory_size_bits
        memory_size_bits = logb2(MEMORY_SIZE)
        self.cache_size_bits = logb2(CACHE_SIZE)
        self.cache_block_size_bits = logb2(CACHE_BLOCK_SIZE)
        self.index_length = logb2(NUM_SETS)
        self.block_offset_length = logb2(CACHE_BLOCK_SIZE)
        print('-----------------------------------------')
        print(f'cache size = {CACHE_SIZE}')
        print(f'block size = {CACHE_BLOCK_SIZE}')
        print(f'#blocks = {NUM_BLOCKS}')
        print(f'#sets = {NUM_SETS}')
        print(f'associativity = {ASSOCIATIVITY}')
        print(f'memory_size_bits = {memory_size_bits}')
        print(f'tag length = {16 - self.index_length - self.block_offset_length}')
        if WRITE_BACK:
            print(f'write back')
        else:
            print(f'write through')
        print('-----------------------------------------')
        print()

    #----------------------------------------------------------------------
    # pull out the tag, index, and block offset from an address

    def decode_address(self, A):
        tag = A >> (self.index_length + self.block_offset_length)

        # index is the set number
        index = (A // CACHE_BLOCK_SIZE) & (NUM_SETS - 1)
        # offset in block is lowest bits
        block_offset = A & (CACHE_BLOCK_SIZE - 1)

        return [tag, index, block_offset]

#======================================================================
# helper function: log base two, in integer arithmetic

def logb2(val):
    i = 0
    assert val > 0
    while val > 0:
        i = i + 1
        val = val >> 1
    return i-1

#======================================================================
# helper function

def binary_to_string(addrlen, val):
    bits = ''
    for i in range(addrlen):
        bit = val & 1
        if bit == 0:
            bits = '0' + bits
        else:
            bits = '1' + bits
        val = val // 2

    return bits
#======================================================================
# helper function to add tags to the tag queue
def enqueue(tag, tag_queue):
    if tag in tag_queue:
        tag_queue.remove(tag)
        tag_queue.append(tag)
        return
    for b in range(len(tag_queue)):
        if tag_queue[b] == -1:
            tag_queue[b] = tag
            return
    tag_queue.pop(0)
    tag_queue.append(tag)


#======================================================================
# convert the four bytes in source[start:start+size] to a
# little-endian integer

def bytes_to_word(source, start, size):
    word = 0
    mult = 1
    for i in range(size):
        word = word + mult * source[start+i]
        #print(f'source[{start+i}] = {source[start+i]}; word is now {word}')
        mult = mult * 256
    return word

#======================================================================
# convert the integer in word to a little-endian byte sequence
# and put it in dest[start:start+size]

def word_to_bytes(dest, start, word, size):
    for i in range(size):
        v = word % 256
        dest[i+start] = v
        word = word // 256

#======================================================================
# access_type is READ or WRITE
# word is unused for READ; word is the actual data for WRITE

def access_memory(address, word, access_type):
    global cache
    assert address < MEMORY_SIZE
    if address & 0x3 != 0:
        print(f'alignment error! address={address}')
        assert address & 0x3 == 0

    [tag, index, block_offset] = cache.decode_address(address)
    range_low = (address >> cache.cache_block_size_bits) * CACHE_BLOCK_SIZE
    range_high = range_low + CACHE_BLOCK_SIZE - 1

    block_index = -1
    found = False
    empty = False
    # find the block index
    for b in range(ASSOCIATIVITY):
        # check if the cache block is not full
        # make sure the tag is valid if there is a miss set the block index to the index of the empty block if not empty set to lRU
        if cache.sets[index].blocks[b].tag == tag and cache.sets[index].blocks[b].valid:
            block_index = b
            found = True
            break

    if not found:
        for b in range(ASSOCIATIVITY):
            if cache.sets[index].blocks[b].tag == -1:
                block_index = b
                empty = True
                break

        for b in range(ASSOCIATIVITY):
            if not empty:
                replace = cache.sets[index].tag_queue[0]
                for b in range(ASSOCIATIVITY):
                    if cache.sets[index].blocks[b].tag == replace:
                        block_index = b

    # READ:
    # if tag is found and the block is valid, then get the value and done
    # else
    #   // need to read a block from memory
    #   if there is a free block in this set, then read
    #   else find a target block and replace
    #
    # WRITE:
    # if tag is found then write to cache
    # else
    #   if there is a free block, then read the block in and write the value
    #   else find a target block and replace and then write the value

    if found:
        # put tag in the tag queue -- for associative cache. the one being accessed right now needs to be in the last
        # position and all other tags need to be shifted
        enqueue(tag, cache.sets[index].tag_queue)

        if access_type == AccessType.READ:
            if not cache.sets[index].blocks[block_index].valid:
                print('error: tag found in cache, but block is not valid')
                assert cache.sets[index].blocks[block_index].valid

            # the word we want from the cache starts at
            # cache.sets[index].blocksp[block_index].data[block_offset]
            memval = bytes_to_word(
                source = cache.sets[index].blocks[block_index].data,
                start = block_offset, size = WORDLENGTH)
            print(f'read hit [addr={address} index={index} block_index={block_index} tag={tag}: word={memval} ({range_low} - {range_high})]')
            rtnval = memval

        else: # write hit
            if WRITE_BACK:
                # tag queue already updated
                cache.sets[index].blocks[block_index].dirty = True
                #todo:write the word to the cache string at
                word_to_bytes(cache.sets[index].blocks[block_index].data, block_offset, word, WORDLENGTH)

            else:
                #write to the cache and the memory
                #todo: change the way write to cache
                word_to_bytes(cache.sets[index].blocks[block_index].data, block_offset, word, WORDLENGTH)

                block_address = (cache.sets[index].blocks[block_index].tag << (cache.index_length + cache.block_offset_length)) | (index << cache.block_offset_length)
                memory[block_address:block_address + CACHE_BLOCK_SIZE] = cache.sets[index].blocks[block_index].data[:]
            rtnval = None

    # otherwise, we have cache miss

    # We're reading into an empty block
    else:
        if empty:
            #set block tag = decoded tag
            cache.sets[index].blocks[block_index].tag = tag

            #set block valid
            cache.sets[index].blocks[block_index].valid = True

            enqueue(tag, cache.sets[index].tag_queue)

            # read the block from memory into cache
            base_address = (address >> cache.cache_block_size_bits) * CACHE_BLOCK_SIZE
            for j in range(CACHE_BLOCK_SIZE):
                cache.sets[index].blocks[block_index].data[j] = memory[base_address + j]

            if access_type == AccessType.READ:
                memval = bytes_to_word(
                    source = cache.sets[index].blocks[block_index].data,
                    start = block_offset, size = WORDLENGTH)
                print(f'read miss [addr={address} index={index} block_index={block_index} tag={tag}: word={memval} ({range_low} - {range_high})]')
                rtnval = memval
            else:
                #cache write miss
                if WRITE_BACK:
                    cache.sets[index].blocks[block_index].dirty = True
                    # todo:write the word to the cache string at
                    word_to_bytes(cache.sets[index].blocks[block_index].data, block_offset, word, WORDLENGTH)

                else:
                    # write to the cache and the memory
                    # todo: change the way write to cache
                    word_to_bytes(cache.sets[index].blocks[block_index].data, block_offset, word, WORDLENGTH)

                    block_address = (cache.sets[index].blocks[block_index].tag << (
                                cache.index_length + cache.block_offset_length)) | (index << cache.block_offset_length)
                    memory[block_address:block_address + CACHE_BLOCK_SIZE] = cache.sets[index].blocks[block_index].data[
                                                                             :]
                rtnval = None


        elif not empty:
            # need to replace cache block

            target_tag  = cache.sets[index].blocks[block_index].tag

            #check to see if current block is dirty. If so, read it to memory
            if cache.sets[index].blocks[block_index].dirty:
                #read block into memory
                block_address = (cache.sets[index].blocks[block_index].tag << (
                        cache.index_length + cache.block_offset_length)) | (index << cache.block_offset_length)
                memory[block_address:block_address + CACHE_BLOCK_SIZE] = cache.sets[index].blocks[block_index].data[:]

            # read in the new block from memory into cache
            base_address = (address >> cache.cache_block_size_bits) * CACHE_BLOCK_SIZE
            for j in range(CACHE_BLOCK_SIZE):
                cache.sets[index].blocks[block_index].data[j] = memory[base_address + j]

            #set block tag = decoded tag
            cache.sets[index].blocks[block_index].tag = tag

            #set block valid
            cache.sets[index].blocks[block_index].valid = True

            #set block clean
            cache.sets[index].blocks[block_index].dirty = False

            #enqueue the new tag
            enqueue(tag, cache.sets[index].tag_queue)

            rtnval = None

            if access_type == AccessType.READ:
                # fetch from memory
                memval = bytes_to_word(
                    source=memory, start=address, size=WORDLENGTH)
                print(
                    f'read miss + replace [addr={address} index={index} tag={tag}: word={memval} ({range_low} - {range_high})]')
                rtnval = memval

            print(f'evict tag {target_tag} in block_index {block_index}')
            print(f'read in ({base_address} - {base_address + CACHE_BLOCK_SIZE - 1})')
    print(f"{cache.sets[index].tag_queue}\n")
    return rtnval


#======================================================================

def read_word(address):
    # from address, compute the tag t, index i and block offset b
    return access_memory(address, None, AccessType.READ)

#======================================================================

def write_word(address, word):
    access_memory(address, word, AccessType.WRITE)

#======================================================================

def part_one_test():
    # direct mapped cache
    for addr in [0, 0, 60, 64, 1000, 1028, 12920, 12924, 12928]:
        word = read_word(addr)
        print(f'=> address = {addr} <{binary_to_string(16, addr)}>; word = {word}')

#======================================================================
def part_two_test():

    read_word(1152)
    read_word(2176)
    read_word(3200)
    read_word(4224)
    read_word(5248)
    read_word(7296)
    read_word(4224)
    read_word(3200)
    write_word(7312, 17)
    read_word(7320)
    read_word(4228)
    read_word(3212)
    write_word(5248, 5)
    read_word(5248)
    write_word(8320, 7)
    read_word(8324)
    read_word(9344)
    read_word(11392)
    read_word(16512)
    read_word(17536)
    read_word(8320)
    read_word(17536)
    read_word(17532)

#======================================================================

def main():
    global cache
    cache = Cache(NUM_SETS, ASSOCIATIVITY, CACHE_BLOCK_SIZE)
    # prefill memory: the word at memory[a] will be a
    for i in range(MEMORY_SIZE // 4):
        word_to_bytes(dest = memory, start = 4*i, word = 4*i, size = WORDLENGTH)

    part_two_test()

#======================================================================

if __name__ == '__main__':
    main()
