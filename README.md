# Preliminary analysis
## Polymorphism
Предварительно исследуя семпл в отладчике , в точке входа можно заметить выделение памяти и копирование семпла в эту область памяти , а так же в конце можно увидеть ```jmp eax```.
![image](https://github.com/user-attachments/assets/ecde3b4b-98e3-46a1-8cf1-3e1891373b8b)
Поэтому для дальнейшего стат. анализа, нам необходимо сдампить уже рассшифрованный семпл.
Прыгаем в ```eax``` и попадаем на обработчик . Анализировать обработчик не имеет особого смысла , поэтому пробуем вернуться из обработчика. Нажимаем ctrl + f9 и попадаем на ret
![image](https://github.com/user-attachments/assets/d7e591a5-b776-4184-9244-08900bc56e98)
Как и ожидалось , обработчик возвращает управление основному модулю.\
Схематично это можно представить так
![image](https://github.com/user-attachments/assets/851df5ca-89c4-4a4f-9e0d-f559f8d6fc08)
Теперь мы можем сдампить уже рассшифрованный модуль используя Scylla , для OEP возьмем тот адрес , который лежал на стеке.

## Strings
Все строки зашифрованы на стадии компиляции и расшифровываются на стеке во время исполнения.
![image](https://github.com/user-attachments/assets/abfccb8e-381f-4587-bef8-8fd2b0c57ed6)

## Import
Импорт зашифрован. Для получение используется функция , которая принимает индекс библиотеки и хеш.\
![image](https://github.com/user-attachments/assets/aaef868f-d5f5-498e-80cc-f4c3254208ee)
![image](https://github.com/user-attachments/assets/f4d2df87-7a75-4015-9abe-9ec171731c8b)
![image](https://github.com/user-attachments/assets/4bfd06e7-5755-4dcd-90cb-a21dd1315df2)
Хеш создается на стадии компиляции используя имя процедуры . Этот хеш используется для поиска нужной процедуры методом перебора таблцы экспорта.

# Static analyze
## Anti - sandbox techniques
![image](https://github.com/user-attachments/assets/1e37f42b-b048-4610-a41d-07656fff0495)
### ```cpuid```
Данный трюк выполняется с ```eax```=1 в качестве входа, возвращаемое значение описывает возможности процессора.
31-й бит ```ecx``` на физической машине будет равен 0. На гостевой виртуальной машине оно будет равно 1.

### ```sidt``` & ```sgdt```
Два данных трюка проверяют критические таблицы OS . Interrupt descriptor table и global descriptor table . Поскольку на реальных машинах базовый адрес таблиц
расположен ниже в памяти, чем на виртуальных. Проверяет 1-й байт базы таблицы. Не работает на vmware v12+

### ```str```
Данный трюк проверяет Task Register , т.к все процессоры x86 могут управлять задачами так же, как это делает операционная система.\
То есть сохранение состояния задачи и его восстановление при повторном выполнении этой задачи. 
Все состояния задачи хранятся в TSS(https://ru.wikipedia.org/wiki/TSS). На каждую задачу приходится один TSS.
Cегмент селектора, который был возвращен из ```str```, указывает на TSS настоящей задачи.
Проверяет первые 2 байта на ```0x4000```. Не работает на vmware v12+

### ```smsw```
Данный трюк , проверяет Machine Status Word , информации про него мало [тык](https://github.com/rrbranco/blackhat2012/blob/master/Csrc/VMDetection/VMDetection/VMDetection.cpp#L89).\ 
Но Суть такая же как у ```sidt``` и ```sgdt```

## Malware behavior
### C2 
CnC сервер , можно увидеть поставив break на ```InternetConnectA``` . Но поскольку C2 протух , смысла от него особого нет
![image](https://github.com/user-attachments/assets/cd893220-5610-408d-9792-3010e2200fcd)
Малварное поведение определяется его обработчиками , которые отвечают за кражу тех или иных данных разберем основные.
![image](https://github.com/user-attachments/assets/3598ddae-2af3-49d2-8373-1b4cfcfcce83)

### Screenshots
Данный обработчик отвечает за создание скриншотов , на каждом сущ. мониторе. 
Используя EnumDisplayMonitors , перебирает каждый монитор в своем обработчике
![image](https://github.com/user-attachments/assets/11dce231-fa9e-43a1-918c-522b4d03bc57)\
Сам скирншот создается через BltBlt . Больше информации [тут](https://www.unknowncheats.me/forum/battlefield-1-a/188209-bitblt-screenshots.html)\
![image](https://github.com/user-attachments/assets/17bb891c-1e7a-41ea-ba7b-ccf97c76d493)

### CryptoWallets
Данный обработчик отвечает за кражу данных крипто-кошельков . Ищет файлы в
* $(HOMEPATH)\AppData\Roaming\Electrum\wallets
* $(HOMEPATH)\AppData\Roaming\MultiBit
* $(HOMEPATH)\AppData\Roaming\Armory
* $(HOMEPATH)\AppData\Roaming\Ethereum\keystore
* $(HOMEPATH)\AppData\Roaming\bytecoin
* $(HOMEPATH)\AppData\Roaming\Jaxx\Local Storage
* $(HOMEPATH)\AppData\Roaming\com.liberty.jaxx\Local Storage\leveldb
* $(HOMEPATH)\AppData\Roaming\atomic\Local Storage\leveldb
* $(HOMEPATH)\AppData\Roaming\Exodus
* $(HOMEPATH)\AppData\Roaming\DashCore
* $(HOMEPATH)\AppData\Roaming\Bitcoin
* $(HOMEPATH)\AppData\Roaming\WalletWasabi
* $(HOMEPATH)\AppData\Roaming\Daedalus Mainnet
* $(HOMEPATH)\documents\Monero

### Steam
Данный обработчик отвечает за кражу данных Steam . Ищет SteamPath в реестре HKEY_CURRENT_USER\Software\Valve\Steam 
Если находит , крадет все файлы по пути \config\*.vdf. По такой же аналогии работают остальные обработчики
* Telegram
* Discord
* Jabber
* Foxmail
* Outlook
* Filezilla

### Internet Explorer
Данный обработчик крадет данные IE используя vaultcli библиотеку. Пример эксплуатации [тык](https://github.com/twelvesec/passcat/blob/master/passcat/libvaultie.cpp#L148)
![image](https://github.com/user-attachments/assets/cbd3f5b5-46cc-4abf-862d-551755f4a5f2)

### PC Information
Данный обработчик собирают основную информацию с ПК.
#### UID/HWID
![image](https://github.com/user-attachments/assets/e5625998-96c3-419e-803e-88e1170accd3)
#### Os version 
![image](https://github.com/user-attachments/assets/10101eef-756c-4367-8219-261eb83dcd1f)
#### Username
![image](https://github.com/user-attachments/assets/7ed29bb9-a68e-44ab-a52a-1f106d69b8ca)
#### Computer name
![image](https://github.com/user-attachments/assets/89b49843-2d0c-42f5-b7c1-dba1c4ac7054)
#### Primary domain
![image](https://github.com/user-attachments/assets/3ca5b359-7aa2-44ba-b0e9-93cd7d4cdbb8)
#### Support languages
![image](https://github.com/user-attachments/assets/39262732-b321-43fa-8e1e-3dc3e2b707b9)
#### CPU vendor information
![image](https://github.com/user-attachments/assets/163895cf-8661-485a-82c9-810e4dc80d35)
#### GPU name
![image](https://github.com/user-attachments/assets/d3487756-25fa-4d4e-800c-08a07506d340)
#### Ram size
![image](https://github.com/user-attachments/assets/5669315d-e2c8-448c-b64d-dee23cbd8280)
### Display resolution
![image](https://github.com/user-attachments/assets/bbb89e6e-4abe-4b9f-bd15-a4b882d412d1)

## Conclusion
Что бы замести следы , малварь использует след. комманду ```cmd.exe /c timeout /t 3  & del /f /q ...```
Она означает ждать 3 секунды, а затем удалить малварный файл без запроса подтверждения.
![image](https://github.com/user-attachments/assets/2b010885-31af-46a5-94ca-32972d857e33)
Так же прикрепляю .idb дампа , на котором проводился анализ. 
