Чтобы создать файл packets.pcap были использованы команды:

```bash
$ ./gen_records.sh records.txt
$ python3 pcap_generator_from_csv.py -i records.txt -o example3.pcap
```

См. [pcap_generator](https://github.com/cslev/pcap_generator)