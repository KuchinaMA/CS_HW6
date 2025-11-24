# Fake DNS + Traceroute Song Emulator

Эмулятор работы traceroute с подменой DNS записей для вывода текста песни.

## Описание

Программа перехватывает UDP пакеты (DNS и traceroute) и ICMP Echo запросы, эмулируя поведение маршрутизаторов и DNS сервера. При выполнении `traceroute` на целевой домен выводится текст песни **Green Day – Boulevard of Broken Dreams** вместо обычных IP адресов.

## Принцип работы
- Перехватывает DNS‑запросы к `rerand0m.ru` и подставляет поддельный IP  
- Эмулирует hops: отвечает на traceroute‑пакеты как будто это разные маршрутизаторы  
- Подменяет PTR‑запросы → для каждого hop возвращает доменное имя из песни  
- Отвечает на ping (`ICMP Echo`) к поддельному IP  
- Остальной трафик не трогает и пропускает как есть

## Требования
- Python 3
- `scapy`

## Запуск
Для схемы из семинара 5:
`Alpine-1` --- `Alpine2` --- `Cloud`

На `Alpine-2` выполнить:
```
python3 fake_dns_traceroute.py --iface eth0
```

На `Alpine-1`:
```
traceroute rerand0m.ru
``