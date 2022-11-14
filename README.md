# Описание
xdpfw - это файервол (межсетевой экран) с фильтрацией пакетов без запоминания состояния. 

В его основе лежит запущенная в ядре линукса виртуальная машина eBPF, а также фреймворк XDP, позволяющий обрабатывать сетевые пакеты как только они попадают на сетевой интерфейс, обходя сетевой стек.

Поддерживается фильтрация только пакетов IP версии 4 с протоколами ICMP, TCP и UDP. Остальные пакеты пропускаются в сетевой стек.

Реализованные в xdpfw фильтры представляют собой набор критериев, среди которых:

* действие permit (разрешить) или deny (отклонить);
* тип протокола L4: ICMP, TCP, UDP;
* номера портов источника и назначения, также возможно задание диапазона портов;
* IP-адреса источника и назначения, также возможно задание ряда адресов путём наложения маски wildcard подобно [маскам из списков доступа Cisco](https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html).

Можно задать до 128 фильтров. Фильтры применяются к пакету в том порядке, в котором были добавлены, до первого совпадения критериев.

## xdp-tools
В проекте используется исходный код [xdp-tools](https://github.com/xdp-project/xdp-tools):

* lib/libxdp - библиотека для загрузки программ XDP, опирающаяся на libbpf.
* lib/params.h - разбор аргументов командной строки и запуск команд (start, stop, flist и др.).
* lib/logging.h - логирование по уровням warn, info, debug.
* lib/stats.h, headers/xdp/xdp_stats_kern_user.h, headers/xdp/xdp_stats_kern.h - сбор статистики по XDP действиям (XDP_DROP, XDP_PASS и др.).

В директории /xdp-tools представлен немного модифицированный исходный код [релиза 1.2.8](https://github.com/xdp-project/xdp-tools/releases/tag/v1.2.8): исключены утилиты xdp-loader, xdp-filter, xdp-dump, изменён сценарий сборки lib/common.mk для поддержки раздельной компиляции утилиты пространства пользователя, несколько других незначительных изменений.


# Сборка
## Скачивание проекта
Скачивание проекта и инициирование подмодуля libbpf:
```bash
git clone https://github.com/Dolecor/ebpf-xdp-firewall.git
cd ebpf-xdp-firewall/
git submodule update --init
```

## Зависимости
Для сборки необходимы следующие пакеты:
```bash
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
```

> Примечание: необходимо, чтобы пакеты clang и llvm были версии 10+, а также чтобы в ядре была поддержка BPF Type Format (например, Ubuntu 20.10, Debian 11 (amd64/arm64)). Подробнее о зависимостях: [libbpf github](https://github.com/libbpf/libbpf/#bpf-co-re-compile-once--run-everywhere).


## Процесс сборки
Для сборки необходимо выполнить команду `make` в корне проекта.

В результате, помимо промежуточных объектных файлов, будут собраны два основных файла:

* src/xdpfwctl - утилита пространства пользователя.
* src/xdpfw_kern.o - XDP программа.

Для очистки проекта: `make xdpfw-clean`.

# Запуск xdpfw
Утилита xdpfwctl выступает в роли интрефейса между пользователем и программой XDP.

Она предоставляет следующие команды: start, stop, status, flist, fadd, frm, reset.

```bash
$ ./xdpfwctl help
Usage: xdpfwctl COMMAND [options]

COMMAND can be one of:
       start       - start firewall on an interface
       stop        - stop firewall on an interface
       status      - print status of firewall on an interface
       flist       - list filters of firewall on an interface
       fadd        - add filter to firewall on an interface
       frm         - remove filter from firewall on an interface
       reset       - reset stats and filters of firewall on an interface
       help        - show this help message

Use 'xdpfwctl COMMAND --help' to see options for specific command
```

## Команда start
> Команду start необходимо запускать из директории с утилитой xdpfwctl, там же должна находится программа xdpfw_kern.o.

Команда start загружает XDP программу xdpfw_kern.o на указанный интерфейс.

```bash
$ ./xdpfwctl start --help

Usage: xdpfwctl start [options] <ifname>

 Start xdpfw (load XDP program) on an interface

Required parameters:
  <ifname>                  Start on device <ifname>

Options:
 -v, --verbose              Enable verbose logging (-vv: more verbose)
     --version              Display version information
 -h, --help                 Show this help
```

## Команда stop
Команда stop выгружает XDP программу xdpfw с указанного интерфейса.

```bash
$ ./xdpfwctl stop --help

Usage: xdpfwctl stop [options] <ifname>

 Stop xdpfw (unload XDP program) on an interface

Required parameters:
  <ifname>                  Stop on device <ifname>

Options:
 -v, --verbose              Enable verbose logging (-vv: more verbose)
     --version              Display version information
 -h, --help                 Show this help
```

## Команда status
Команда status выводит информацию о статусе запущенной на интерфейсе программы xdpfw.

```bash
$ ./xdpfwctl status --help

Usage: xdpfwctl status [options] <ifname>

 Print status and stats of xdpfw on an interface

Required parameters:
  <ifname>                  Print status on device <ifname>

Options:
 -s, --stats                Print number of denied packets
 -f, --filters              Print number of active filters
 -v, --verbose              Enable verbose logging (-vv: more verbose)
     --version              Display version information
 -h, --help                 Show this help
```

## Команда reset
Команда reset сбрасывает собранную статистику и/или список фильтров.

```bash
$ ./xdpfwctl reset --help

Usage: xdpfwctl reset [options] <ifname>

 Reset xdpfw on an interface

Required parameters:
  <ifname>                  Reset on device <ifname>

Options:
 -s, --stats                Reset stats
 -f, --filters              Reset filter list
 -v, --verbose              Enable verbose logging (-vv: more verbose)
     --version              Display version information
 -h, --help                 Show this help
```

## Команда flist (filter list)
Команда flist выводит список фильтров на указанном интерфейсе.

```bash
$ ./xdpfwctl flist --help

Usage: xdpfwctl flist [options] <ifname>

 List filters of xdpfw on an interface

Required parameters:
  <ifname>                  List on device <ifname>

Options:
 -v, --verbose              Enable verbose logging (-vv: more verbose)
     --version              Display version information
 -h, --help                 Show this help
```

## Команда fadd (filter add)
Команда fadd добавляет фильтр в список.

```bash
$ ./xdpfwctl fadd --help

Usage: xdpfwctl fadd [options] <ifname> <action> <proto>

 Add filter to xdpfw on an interface

Required parameters:
  <ifname>                  Add on device <ifname>
  <action>                  Specify <action> of filter (valid values: deny,permit)
  <proto>                   Specify <proto> of filter (valid values: icmp,tcp,udp)

Options:
     --srcip <ip>           Specify source ip of filter
     --srcwc <wcard>        Specify wildcard of source ip (default: 0.0.0.0 (host))
     --dstip <ip>           Specify dest ip of filter
     --dstwc <wcard>        Specify wildcard of dest ip (default: 0.0.0.0 (host))
     --sport <port>         Specify source port of filter (default: 0 (any))
     --spend <port>         Specify end of source port range (default: 0 (==sport))
     --dport <port>         Specify dest port of filter (default: 0 (any))
     --dpend <port>         Specify source port of filter (default: 0 (==dport))
 -i, --id <id>              Specify <id> to insert at list of filters
 -v, --verbose              Enable verbose logging (-vv: more verbose)
     --version              Display version information
 -h, --help                 Show this help
```

## Команда frm (filter remove)
Команда frm удаляет фильтр из списка по индексу. Индексы фильтров можно узнать, выполнив команду flist.

```bash
$ ./xdpfwctl frm --help

Usage: xdpfwctl frm [options] <ifname> <id>

 Remove filter from xdpfw on an interface

Required parameters:
  <ifname>                  Remove from device <ifname>
  <id>                      Specify <id> of filter

Options:
 -v, --verbose              Enable verbose logging (-vv: more verbose)
     --version              Display version information
 -h, --help                 Show this help
```

# Примеры использования
## Пример 1: фильтрация ICMP
> Данный пример выполняется на интерфейсе, у которого есть выход в Интернет.

1. Сделаем ping example.com и из вывода получим ip адрес:
    ```bash
    $ ping example.com -c 1
    PING example.com (93.184.216.34) 56(84) bytes of data.
                      ^^^^^^^^^^^^^
    64 bytes from 93.184.216.34 (93.184.216.34): icmp_seq=1 ttl=56 time=154 ms

    --- example.com ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 154.174/154.174/154.174/0.000 ms
    ...
    ```
2. Запустим xdpfw на интерфейсе и добавим фильтр со следующими критериями: отклонять пакеты с ICMP; адрес источника - адрес, полученный в пункте 1; адреса назначения - ip машины, с которой запускается ping:
   ```bash
    $ sudo ./xdpfwctl start enp3s0
    No XDP program loaded on device
    xdpfw started on interface 'enp3s0' with prog id 257

    $ sudo ./xdpfwctl fadd enp3s0 deny icmp \
    --srcip 93.184.216.34 --dstip 192.168.1.107

    $ sudo ./xdpfwctl flist enp3s0
    | id| type | proto |     src ip    | sp beg |     dst ip    | dp beg |
    |   |      |       |    wildcard   | sp end |    wildcard   | dp end |
    +---+------+-------+---------------+--------+---------------+--------+
    |  0|deny  | icmp  |93.184.216.34  | any    |192.168.1.107  | any    |
    |   |      |       |host           |        |host           |        |
    +---+------+-------+---------------+--------+---------------+--------+
    |  1|end   | ---   |---            | ---    |---            | ---    |
   ```
   >Вместо указания конертного адреса назначения (`--dstip 192.168.1.107`) можно указать адрес "любой", указав wildcard 255.255.255.255 (`--dstwc 255.255.255.255`)

    Теперь при запуске команды `ping <ip из п.1>` ответ получен не будет:
    ```bash
    $ ping 93.184.216.34 -c 1
    PING 93.184.216.34 (93.184.216.34) 56(84) bytes of data.

    --- 93.184.216.34 ping statistics ---
    1 packets transmitted, 0 received, 100% packet loss, time 0ms
    ```

    При этом, если указать другой адрес, то ответ будет получен:
    ```bash
    $ ping google.com -c 1
    PING google.com (74.125.205.100) 56(84) bytes of data.
    64 bytes from le-in-f100.1e100.net (74.125.205.100): icmp_seq=1 ttl=108 time=20.0 ms

    --- google.com ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 20.025/20.025/20.025/0.000 ms
    ```

    Проверим статистику файервола:
    ```bash
    $ sudo ./xdpfwctl status enp3s0 -sf
   
    STATUS:
    xdpfwctl is started on interface 'enp3s0'
    Load mode: multiprog
    Dispatcher id: 262
    Prog id: 269
    Attach mode: skb

    STATS:
    Number of denied packets: 1

    FILTERS:
    Number of active filters: 1
    To see the list itself, run 'xdpfwctl flist <ifname>'
    ```

    В STATS видим 1 пакет, который был отклонён после вызова `ping 93.184.216.34 -c 1` после добавления фильтра.

3. Удалим фильтр и попробуем ещё раз выполнить ping.
    ```bash
    $ sudo ./xdpfwctl frm enp3s0 0

    $ sudo ./xdpfwctl flist enp3s0
    | id| type | proto |     src ip    | sp beg |     dst ip    | dp beg |
    |   |      |       |    wildcard   | sp end |    wildcard   | dp end |
    +---+------+-------+---------------+--------+---------------+--------+
    |  0|end   | ---   |---            | ---    |---            | ---    |

    $ ping 93.184.216.34 -c 1
    PING 93.184.216.34 (93.184.216.34) 56(84) bytes of data.
    64 bytes from 93.184.216.34: icmp_seq=1 ttl=56 time=155 ms

    --- 93.184.216.34 ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 155.402/155.402/155.402/0.000 ms
    ```

## Пример 2: фильтрация UDP
> С помощью этого примера можно также проверить возможность фильтрации пакетов с TCP, убрав в вызовах команды `nc` опцию -u, а при определении фильтра заменить udp на tcp.

Для демонстрации данного примера воспользуемся [тестовой средой xdp-tutorial](https://github.com/xdp-project/xdp-tutorial/tree/master/testenv).

Конфигурация тестовой среды:

```
+-----------------------------+                          +-----------------------------+
| Root namespace              |                          | Testenv namespace 'test'    |
|                             |       From 'test'        |                             |
|                    +--------+ TX->                RX-> +--------+                    |
|                    | test   +--------------------------+  veth0 |                    |
|                    +--------+ <-RX                <-TX +--------+                    |
|                             |       From 'veth0'       |                             |
+-----------------------------+                          +-----------------------------+
```

Создадим тестовую среду и из вызовов `ip addr` получим адреса созданных интерфейсов:

```bash
$ eval $(./testenv.sh alias)
$ t setup --name test --legacy-ip
$ t exec -- ip addr show
    1: lo: ...
    2: veth0@if5: ...
->      inet 10.11.1.2/24 scope global veth0
            valid_lft forever preferred_lft forever
...
```

```bash
$ ip addr
    1: lo: ...
    2: enp3s0: ...
    ...
    5: test@if2: ...
->      inet 10.11.1.1/24 scope global test
            valid_lft forever preferred_lft forever
...
```

1. Загрузим программу xdpfw на интерфейс test:

    ```bash
    $ sudo ./xdpfwctl start test
    No XDP program loaded on device
    xdpfw started on interface 'test' with prog id 227
    ```

2. Запустим `nc` на интерфейсе test в режиме прослушивания:
    ```bash
    $ nc -ul 10.11.1.1 1234
    ```
3. Из тестовой среды установим соединение с 10.11.1.1:1234 и произведём ввод:
    ```bash
    $ t enter

    root@X:.../xdp-tutorial/testenv# nc -u 10.11.1.1 1234
    hello
    ```
    На интерфейсе test видим этот ввод.

4. Теперь добавим фильтр со следующими критериями: отклонять пакеты с UDP; адрес источника - 10.11.1.2 (адрес тестовой среды); адреса назначения - любой; порт источника - любой; порт назначения - 1234:
    ```bash
    $ sudo ./xdpfwctl fadd test deny udp \
    --srcip 10.11.1.2 --dstwc 255.255.255.255 \
    --sport 0 --dport 1234

    $ sudo ./xdpfwctl flist test
    | id| type | proto |     src ip    | sp beg |     dst ip    | dp beg |
    |   |      |       |    wildcard   | sp end |    wildcard   | dp end |
    +---+------+-------+---------------+--------+---------------+--------+
    |  0|deny  | udp   |10.11.1.2      | any    |any            | 1234   |
    |   |      |       |host           |        |               | eq     |
    +---+------+-------+---------------+--------+---------------+--------+
    |  1|end   | ---   |---            | ---    |---            | ---    |
    ```
    И уже не будем получать ввод.
    
    При этом, естественно, запустив прослушивание на другом порту ввод будет доставляться.

> Чтобы уничтожить тестовую среду:
> ```bash
> root@X:.../xdp-tutorial/testenv# exit
> $ t teardown
> Tearing down environment 'test'
> ```

## Пример 3: фильтрация по диапазонам IP адресов и портов

Пусть есть сервер с адресом 10.1.1.1, у которого на TCP портах 1024-1038 запущены какие-то сервисы.

Необходимо запретить доступ к этим сервисам для всех клиентов, за исключением клиентов из подсети 10.2.2.0/28 (10.2.2.0 - 10.2.2.15).

Для этого примера сгенерирован отладочный трафик testing/example3.pcap. Он состоит из следующих групп пакетов:
   1. 15 пакетов, которые поступают из разрешенной подсети и имеют порты назначения из запрещенного диапазона;
   2. 15 пакетов, которые поступают из разрешенной подсети и имеют порты назначения за пределами запрещенного диапазона;
   3. 15 пакетов, которые поступают не из разрешенной подсети и имеют порты назначения из запрещенного диапазона;
   4. 15 пакетов, которые поступают не из разрешенной подсети и имеют порты назначения за пределами определенного диапазона.


Шаги выполнения примера:

1. Загрузим программу xdpfw на интерфейс lo:
    ```bash
    $ sudo ./xdpfwctl start lo
    No XDP program loaded on device
    xdpfw started on interface 'lo' with prog id 97
    ```

2. Применим к файерволу два списка фильтров.
   1. В пустой список добавим фильтр, который отклоняет TCP пакеты с портом назначения в диапазоне 1024-1038:
        ```bash
        $ sudo ./xdpfwctl fadd lo deny tcp \
        --srcwc 255.255.255.255 --dstip 10.1.1.1 \
        --sport 0 --dport 1024 --dpend 1038

        $ sudo ./xdpfwctl flist lo
        | id| type | proto |     src ip    | sp beg |     dst ip    | dp beg |
        |   |      |       |    wildcard   | sp end |    wildcard   | dp end |
        +---+------+-------+---------------+--------+---------------+--------+
        |  0|deny  | tcp   |any            | any    |10.1.1.1       | 1024   |
        |   |      |       |               |        |host           | 1038   |
        +---+------+-------+---------------+--------+---------------+--------+
        |  1|end   | ---   |---            | ---    |---            | ---    |
        ```
        
        Отправим отладочный трафик на интерфейс и проврим, сколько пакетов было отброшено:
        ```bash
        $ sudo tcpreplay -i lo ../testing/example3.pcap.64bytes.pcap
        ...
        Actual: 60 packets (4440 bytes) sent in 0.451667 seconds
        Rated: 9830.2 Bps, 0.078 Mbps, 132.84 pps
        Flows: 60 flows, 132.84 fps, 60 flow packets, 0 non-flow
        Statistics for network device: lo
            Successful packets:        60
            Failed packets:            0
            Truncated packets:         0
            Retried packets (ENOBUFS): 0
            Retried packets (EAGAIN):  0

        $ sudo ./xdpfwctl status lo -s
        ...
        STATS:
        Number of denied packets: 30
        ```

        Как и ожидалось, заблокировано 30 пакетов (из группы пакетов 1 и 3).

   2. Теперь в дополнение к фильтру из предыдущего пункта добавим исключение для пакетов, приходящих с адресов 10.2.2.0/28. Разрешающее правило должно идти первее в списке, поэтому необходимо перезаписать список фильтров (`-i 0` при выполнении `fadd` или `xdpfwctl reset lo -f`).
        ```bash
        $ sudo ./xdpfwctl fadd lo permit tcp -i 0 \
        --srcip 10.2.2.0 --srcwc 0.0.0.15 --dstip 10.1.1.1 \
        --sport 0 --dport 1024 --dpend 1038

        $ sudo ./xdpfwctl fadd lo deny tcp \
        --srcwc 255.255.255.255 --dstip 10.1.1.1 \
        --sport 0 --dport 1024 --dpend 1038

        $ sudo ./xdpfwctl flist lo
        | id| type | proto |     src ip    | sp beg |     dst ip    | dp beg |
        |   |      |       |    wildcard   | sp end |    wildcard   | dp end |
        +---+------+-------+---------------+--------+---------------+--------+
        |  0|permit| tcp   |10.2.2.0       | any    |10.1.1.1       | 1024   |
        |   |      |       |0.0.0.15       |        |host           | 1038   |
        +---+------+-------+---------------+--------+---------------+--------+
        |  1|deny  | tcp   |any            | any    |10.1.1.1       | 1024   |
        |   |      |       |               |        |host           | 1038   |
        +---+------+-------+---------------+--------+---------------+--------+
        |  2|end   | ---   |---            | ---    |---            | ---    |
        ```

        Очистим статистику файервола, отправим отладочный трафик и проверим, сколько пакетов будет отброшено:
        ```bash
        $ sudo ./xdpfwctl reset lo -s
        Stats reset

        $ sudo tcpreplay -i lo ../testing/example3.pcap.64bytes.pcap 
        ...
        Actual: 60 packets (4440 bytes) sent in 0.451663 seconds
        Rated: 9830.3 Bps, 0.078 Mbps, 132.84 pps
        Flows: 60 flows, 132.84 fps, 60 flow packets, 0 non-flow
        Statistics for network device: lo
            Successful packets:        60
            Failed packets:            0
            Truncated packets:         0
            Retried packets (ENOBUFS): 0
            Retried packets (EAGAIN):  0

        $ sudo ./xdpfwctl status lo -s
        ...

        STATS:
        Number of denied packets: 15
        ```

        Как и ожидалось, заблокировано 15 пакетов (из группы пакетов 3).

        

# Авторство и лицензия
## Автор
Copyright (c) 2022 Доленко Дмитрий <<dolenko.dv@yandex.ru>>
## Лицензия
Исходный код распространяется под лицензией GPLv2 (см. прилагаемый файл LICENSE).
## Сторонний исходный код
В проекте используется сторонний исходный код:
 * xdp-tools: см. файл xdp-tools/LICENSES