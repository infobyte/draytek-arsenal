meta:
  id: draytek
  file-extension: all
  endian: be
  
seq:
  - id: bin
    type: bin_section
  - id: webfs
    type: webfs_section
    
types:
  u3:
    seq:
      - id: b12
        type: u2
      - id: b3
        type: u1
    instances:
      value:
        value: '(b12 << 12) | b3'
  bin_header:
    seq:
      - id: size
        type: u4
      - id: version_info
        type: u1
      - id: next_section
        type: u3
      - id: rest
        size: 0xf8
    instances:
      adj_size:
        value: (((size + 3) >> 2) -1 ) << 2
      bootloader_version:
        value: version_info >> 4
      product_number:
        value: version_info & 0xf
        
  bootloader:
    seq:
      - id: data
        type: u4
        repeat: until
        repeat-until: _ == 0xa55aa55a
        
  rtos:
    seq:
      - id: rtos_size
        type: u4
      - id: data
        size: rtos_size - 4
      - id: padding
        size: 8 - _io.pos % 8 # Check if there is no other data
        
  dlm:
    seq:
      - id: magic
        contents: DLM/1.0
      - id: data
        size: _parent.header.adj_size - _io.pos
        
  bin_section:
    seq:
      - id: header
        type: bin_header
      - id: bootloader
        type: bootloader
      - id: rtos
        type: rtos
      - id: dlm
        type: dlm
      - id: not_checksum
        type: u4
    instances:
      checksum:
        value: not_checksum ^ 0xffffffff
        
  webfs_header:
    seq:
      - id: size
        type: u4
      - id: next_section
        type: u4
    instances:
      adj_size:
        value: (((size + 3) >> 2) -1 ) << 2
        
  webfs_section:
    seq:
      - id: header
        type: webfs_header
      - id: data
        size: header.next_section
      - id: padding
        size: header.size - header.next_section - 12
      - id: not_checksum
        type: u4
    instances:
      checksum:
        value: not_checksum ^ 0xffffffff
