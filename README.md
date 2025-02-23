# Preliminary analysis
## Polymorphism
Предварительно исследуя семпл в отладчике , в точке входа можно заметить выделение памяти и копирование семпла в эту область памяти , а так же в конце можно увидеть ```jmp eax```.
![image](https://github.com/user-attachments/assets/ecde3b4b-98e3-46a1-8cf1-3e1891373b8b)
Поэтому для дальнейшего стат. анализа, нам необходимо сдампить уже рассшифрованный семпл.
Прыгаем в ```eax``` и попадаем на обработчик . Анализировать обработчик не имеет особого смысла , поэтому пробуем вернуться из обработчика. Нажимаем ctrl + f9 и попадаем на ret
![image](https://github.com/user-attachments/assets/d7e591a5-b776-4184-9244-08900bc56e98)
Как и ожидалось , обработчик возвращает управление основному модулю . Теперь мы можем сдампить уже рассшифрованный модуль используя Scylla , для OEP возьмем тот адрес , который лежал на стеке.\
Схематично это можно представить так
![image](https://github.com/user-attachments/assets/851df5ca-89c4-4a4f-9e0d-f559f8d6fc08)

## Strings
Все строки зашифрованы на стадии компиляции и расшифровываются на стеке во время исполнения.
![image](https://github.com/user-attachments/assets/abfccb8e-381f-4587-bef8-8fd2b0c57ed6)

## Import
Импорт зашифрован. Для получение используется функция , которая принимает индекс библиотеки и хеш имени процедуры.\
![image](https://github.com/user-attachments/assets/aaef868f-d5f5-498e-80cc-f4c3254208ee)
![image](https://github.com/user-attachments/assets/f4d2df87-7a75-4015-9abe-9ec171731c8b)
![image](https://github.com/user-attachments/assets/4bfd06e7-5755-4dcd-90cb-a21dd1315df2)
Хеш создается на стадии компиляции используя имя процедуры . Этот хеш используется для поиска нужной процедуры методом перебора таблцы экспорта.
Теперь мы можем получить весь импорт , изменяя ```eip``` можно пробежаться по всем xref

kernel32.GetUserDefaultLangID
kernel32.FindFirstFileA
kernel32.FindNextFileA
kernel32.FindClose
gdiplus.GdipDisposeImage
gdiplus.GdipFree
gdiplus.GdipCloneImage
gdiplus.GdipCloneImage


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
Проверяет первые 2 байта на 0x4000. Не работает на vmware v12+

### ```smsw```
Данный трюк , проверяет Machine Status Word , информации про него мало [тык](https://github.com/rrbranco/blackhat2012/blob/master/Csrc/VMDetection/VMDetection/VMDetection.cpp#L89). Но Суть такая же как у ```sidt``` и ```sgdt```

## Malware behavior
### C2

