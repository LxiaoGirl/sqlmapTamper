# sqlmapTamper
测试过程中需要绕过各种waf或者全局的过滤机制，因此编写各种适合的tamper。

initialunicodeencode.py 用于将首字母unicode编码，遇到WebKnight防火墙时使用过。

thinkphp0day.py 用于Thinkphp 3.0-3.3 中(in/betwenn）注入过程中绕过TP本身的一些限制与查找。
