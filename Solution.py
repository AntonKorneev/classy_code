#!/usr/bin/env python
# coding: utf-8

# In[1]:


import json as js
import requests as req
from tkinter import filedialog
from tkinter import *
import sys
import pandas as pd
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
import httpagentparser as pars
print("Пожалуйста загрузите файл test.csv")
Tk().withdraw() #указываем путь к выборке
Tk().update()
init_csv = filedialog.askopenfilename(initialdir = "/",title = "Укажите путь к файлу",filetypes = (("csv files","*.csv"),("all files","*.*")))
Tk().destroy()
if len(init_csv)==0:
    print("Не указан .csv файл, выход из программы")
    sys.exit()
df = pd.read_csv(init_csv, sep=';') #превращаем выборку в DataFrame


# In[2]:


def find_mask(df_x,column_name,column_value):
    #Данная функция предназначена для облегчения читаемости кода. Она строит выборку из полученного DataFrame по заданным условиям
    mask = df_x[column_name].values == column_value #для ускорения поиска воспользуемся mask
    temp_dataframe = mask.nonzero()[0]
    return temp_dataframe


# In[3]:


def ip_check(IPv4):
    #Данная функция предназначена для получения подробной информации об IP методом парсинга БД RIPE Network и портала https://check-host.net/
    data = js.loads(req.get("https://rest.db.ripe.net/search.json?query-string="+IPv4).text) #загружаем информацию из БД RIPE при помощи запроса данных в формате JSON
    i,n=0,0
    for data["objects"]["object"][i] in data["objects"]["object"]:
        if data["objects"]["object"][i]["type"]=="inetnum":
            for data["objects"]["object"][i]["attributes"]["attribute"][n] in data["objects"]["object"][i]["attributes"]["attribute"]:
                if data["objects"]["object"][i]["attributes"]["attribute"][n]["name"]=="netname": #ищем нужную строку, содержащую название подсети
                    NetName = data["objects"]["object"][i]["attributes"]["attribute"][n]["value"] #получаем искомое значение
                    break
                n+=1
        elif data["objects"]["object"][i]["type"]=="route": #ищем нужную строку, содержащую адрес подсети
            Subnetwork = data["objects"]["object"][i]["attributes"]["attribute"][0]["value"] #получаем искомое значение, пользуясь тем, что первой строкой всегда идёт адрес подсети
            break
        n=0
        i+=1
    header = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.75 Safari/537.36",
  "X-Requested-With": "XMLHttpRequest"} #эмулируем клиент-браузер, в связи с тем, что сайт отказывается отвечать на прямые запросы программы
    data2 = pd.read_html(req.get("https://check-host.net/ip-info?host="+IPv4+"#ip_info-ip2location", headers=header).text) #загружаем информацию с портала в виде HTML-таблиц (DataFrame)
    Provider,Country,Region,City = data2[2].at[4,1],data2[4].at[5,1], data2[4].at[6,1], data2[4].at[7,1] #пользуемся жёсткой структурой таблиц и получаем искомые значения (Название провайдера, страны, региона и города)
    if len(str(Provider))<5:
        Provider = data2[2].at[3,1] #исправляем потенциальные ошибки
    return [Country, Region, City, Provider, NetName, Subnetwork] #выдаём полученную информацию в виде списка


# In[4]:


def usag_check(UsAg):
    #Данная функция предназначена для получения подробной информации о User Agent клиента при помощи анализа по ключевым словам (httpagentparser + очистка)
    mob_check = {'iPhone', 'iOS', 'Android', 'Windows Phone'}
    while True:
        try:
            IsMobile=pars.detect(UsAg)["os"]["name"] #оказалось, что скрипт считает Android не ос, а платформой
            break
        except KeyError:
            IsMobile="Undefined"
            break
    while True:
        try:        
            OS=pars.detect(UsAg)["platform"]["name"] #поэтому их пришлось поменять местами
            break
        except KeyError:
            OS="Undefined"
            break
    while True:
        try:        
            OS_ver=pars.detect(UsAg)["os"]["version"]
            break
        except KeyError:
            OS_ver="Undefined"
            break
    while True:
        try:        
            Browser=pars.detect(UsAg)["browser"]["name"]
            break
        except KeyError:
            Browser="Undefined"
            break
    while True:
        try:        
            Br_ver=pars.detect(UsAg)["browser"]["version"]
            break
        except KeyError:
            Br_ver="Undefined"
            break
    if IsMobile==None: #методом проб и ошибок было найдено странное исключение, упорядочим его
        IsMobile="Undefined"
    if IsMobile in mob_check or OS in mob_check: #блок проверки на мобильное устройство
        IsMobile=True
    else:
        if IsMobile != "Undefined":
            IsMobile=False
    if OS_ver=="Undefined": #здесь и далее ручная доработка парсинга User Agent библиотеки httpagentparser
        if OS=="Android":
            OS_ver=UsAg[UsAg.find("Android ")+8:UsAg.find(",", UsAg.find("Android ")+8)]
        if OS=="iOS":
            OS_ver=UsAg[UsAg.find("iPhone OS ")+10:UsAg.find(" like Mac", UsAg.find("iPhone OS ")+10)]
        if OS=="Mac OS":
            OS_ver=UsAg[UsAg.find(" ", UsAg.find("Mac OS ")+7)+1:UsAg.find(")", UsAg.find("Mac OS ")+7)]
    elif len(OS_ver)>3 and OS=="Windows":
        OS_ver=UsAg[UsAg.find("NT "):UsAg.find(",", UsAg.find("NT "))]
        if OS_ver=="NT 10.0":
            OS_ver=10
        if OS_ver=="NT 6.3":
            OS_ver=8.1
        if OS_ver=="NT 6.2":
            OS_ver=8
        if OS_ver=="NT 6.1":
            OS_ver=7
        if OS_ver=="NT 6.0":
            OS_ver="Vista"
    if Browser=="Undefined" and OS=="iOS":
        Browser=UsAg[UsAg.rfind(" ")+1:]
        if Browser[:6]=="Mobile":
            Browser,Br_ver="Webkit based browser",Browser[7:]
    if Br_ver=="Undefined" and Browser=="Microsoft Internet Explorer":
        Br_ver=UsAg[UsAg.find("rv:")+3:UsAg.find(")", UsAg.find("rv:"))]    
    return [IsMobile, OS, OS_ver, Browser, Br_ver]


# In[5]:


def calc_helper(df_x, aim_i, true_i, rd_id):
    #Данная функция предназначена для облегчения читаемости кода. Она проводит операции с таблицами устройств одного логина, присваивая реальный идентификатор устройства
    true_el = df_x.at[true_i, "rdev_id"]
    aim_el = df_x.at[aim_i, "rdev_id"]
    if true_el == aim_el == None: #рассмотрим четыре случая: первый - ни один из реальных индентификаторов не определён
        df_x.at[true_i, "rdev_id"]=rd_id
        df_x.at[aim_i, "rdev_id"]=rd_id
        rd_id+=1
    elif true_el == None: #второй - верхний реальный индентификатор не определён
        df_x.at[true_i, "rdev_id"]=df_x.at[aim_i, "rdev_id"]
    elif aim_el == None: #третий - нижний релаьный индентификатор не определён
        df_x.at[aim_i, "rdev_id"]=df_x.at[true_i, "rdev_id"]
    elif true_el != None != aim_el: #последний - оба определены
        result=min(true_el,aim_el)
        aim=max(true_el,aim_el)
        temp_df = df_x.iloc[find_mask(df_x,"rdev_id",aim)]
        for temp_index in temp_df.index: #в таком случае - сольём эти номера вместе (по меньшему)
            df_x.at[temp_index, "rdev_id"]=result
    return rd_id


# In[6]:


def make_a_random_graph(df_x, true_column, aim_column):
    #Данная функция предназначена для визуализации случайного графа (размерности от 4 до 16 вершин) зависимости между двумя заданными параметрами
    inner_df=df_x
    unique_values_list=pd.unique(df_x[[true_column]].values.ravel('K'))
    while len(inner_df)>15 or len(inner_df)<3:
        random_number = np.random.randint(group_count)
        random_value = unique_values_list[random_number]
        inner_df = df_x.loc[find_mask(df_x,true_column,random_value)]
    g=nx.from_pandas_edgelist(inner_df, true_column, aim_column)
    node_size_list=[20000]+[5000 for x in range(len(inner_df))]
    if true_column == "login":
        node_color_list=[0]+[1 for x in range(len(inner_df))]
    else:
        node_color_list=node_size_list
    return nx.draw_kamada_kawai(g, cmap=plt.cm.Pastel1, with_labels=True,node_size=node_size_list,node_color=node_color_list,font_weight="bold")


# In[7]:


df['country'],df['region'],df['city'],df['provider'],df['netname'],df['subnetwork'] = None,None,None,None,None,None #создаём столбцы для
df['isMobile'],df['os'],df['os_ver'],df['browser'],df['br_ver'] = None,None,None,None,None #последующего заполнения данными об IP и User Agent
ip_set=set()
df_new=df #подготавливаем таблицу для будущего .csv файла
ip_inc=df['ip'].str.count(',').sum() #посчитаем, насколько увеличится таблица, если разложить её так, чтобы в строке был только один IP-адрес
fin_row=len(df.index)+ip_inc #посчитаем итоговую длину таблицы
compl_bar={int(fin_row * (x+1) * 0.05) for x in range(19)}
print("Ведётся подготовка файла.csv [скорость неравномерная]")
for row_count in range(fin_row):
    if df_new.ip[row_count][0]=="[": #удалим лишние скобки, если они есть в поле
        ip_num=str(df_new.ip[row_count][1:-1]).split(', ')
    else:
        ip_num=str(df_new.ip[row_count]).split(', ')
    if len(ip_num)>1: #добавим новые строки с другими IP-адресами, если их больше, чем один
        for inner_count in range(len(ip_num)-1):
            df_new = df_new.append(pd.Series([df.device_id[row_count], df.login[row_count], ip_num[inner_count+1], df.user_agent[row_count], None, None, None, None, None, None, None, None, None, None, None], index=df_new.columns ), ignore_index=True)
    df_new.ip[row_count]=ip_num[0]
    if ip_num[0] not in ip_set: #чтобы не перегружать БД лишними запросами - устроим проверку на наличие данных в таблице при помощи множества IP
        ip_info=ip_check(ip_num[0][1:-1])
        ip_set.add(ip_num[0])
    else:
        ip_info = df_new.loc[find_mask(df_new,"ip",ip_num[0]).min()].tolist()[4:10]
    df_new.country[row_count], df_new.region[row_count], df_new.city[row_count], df_new.provider[row_count], df_new.netname[row_count], df_new.subnetwork[row_count] = ip_info #добавляем информацию об IP
    df_new.isMobile[row_count], df_new.os[row_count], df_new.os_ver[row_count], df_new.browser[row_count], df_new.br_ver[row_count] = usag_check(df_new.user_agent[row_count]) #добавляем информацию из User Agent
    if row_count in compl_bar: #выведем процент завершения для пользователя, в связи с длительностью операции
        compl_bar_status = int(100*row_count/fin_row)
        if compl_bar_status != 50:
            compl_bar_status += 1
        print("Выполнено " + str(compl_bar_status) + "%")
print("Выполнено 100%. Сохраните сформированный файл")
ip_set.clear()
Tk().withdraw() 
Tk().update()
task1_path = filedialog.askdirectory(initialdir = "/",title = "Укажите путь сохранения файла")
Tk().destroy()
if len(task1_path)==0:
    print("Не указан путь сохранения, выход из программы")
    sys.quit()
df_new.to_csv(task1_path+"/task_1.csv", sep=';', index=False)


# In[8]:


df_2 = df_new #подготавливаем таблицу для выявления реальных устройств
df_2 = df_2.iloc[0:len(df.index), [0,1,10,11,12,13,14]].drop_duplicates().reset_index(drop=True) #убираем лишние колонки и строки
df_2['rdev_id'], df_2['reason'] = None, None #добавим столбцы для группировки идентификаторов устройств за реальным устройством
un_logs = pd.unique(df_2[["login"]].values.ravel('K')) #формируем массив уникальных логинов
reasons = ["установлена связь между людьми","смена ОС","смена версии ОС","смена браузера","смена версии браузера","полностью совпадают (при разных device_id)"]
reas_set, temp_reas_set = set(), set()
r_id = 1
for un_log in un_logs: #запустим процедуру внутренней проверки (внутри одного логина), найдём DataFrame каждого уникального логина
    inner_counter = 0
    inner_check = df_2.loc[find_mask(df_2,"login",un_log)]
    for true_index in inner_check.index: #сравним каждую строку уникального логина с каждой последующей строкой уникального логина
        reas_set.clear()
        inner_counter +=1
        for temp_counter in range(len(inner_check.index)-inner_counter):
            aim_index=inner_check.index[temp_counter+inner_counter] 
            for inn_column_name in inner_check.columns.values[2:-2]: #сделаем это по столбцам
                true_elem=inner_check.at[true_index, inn_column_name]
                aim_elem=inner_check.at[aim_index, inn_column_name]
                #print(true_elem != aim_elem) #оставляю в коде для облегчения проверки логики программы(1)
                if inn_column_name=="isMobile": #устроим сначала проверку на совпадение реального идентификатора
                    if inner_check.at[true_index, "rdev_id"]==inner_check.at[aim_index, "rdev_id"]!=None:
                        break
                if inn_column_name=="isMobile": #затем - дополнительную проверку на совпадение device_id
                    if inner_check.at[true_index, "device_id"]==inner_check.at[aim_index, "device_id"]:
                        r_id=calc_helper(df_2,aim_index,true_index,r_id)
                        break
                if inn_column_name=="isMobile" and true_elem != aim_elem: #реальное устройство не может быть и мобильным, и стационарным одновременно
                    break
                if inn_column_name=="os" and true_elem != aim_elem: #проверка имени ОС
                    if true_elem=="Mac OS" or aim_elem=="Mac OS": #предполагаем, что Mac OS невозможно поставить на ПК, а Linux/Windows на Mac
                        break
                    else:
                        temp_reas_set.add(1) 
                if inn_column_name=="os_ver" and true_elem != aim_elem: #проверка версии ОС
                    if 1 not in temp_reas_set: #если ОС отличается, сверять версии нет смысла
                        temp_reas_set.add(2)
                if inn_column_name=="browser" and true_elem != aim_elem: #проверка названия браузера
                    if 1 in temp_reas_set: #согласно предположению невозможна одновременная смена ОС и браузера, если не будет обнаружено промежуточных этапов в других записях одного логина
                        temp_reas_set.clear()
                        break
                    elif 2 in temp_reas_set: #та же ситуация с одновременной сменой версии ОС и браузера
                        temp_reas_set.clear()
                        break
                    else:
                        temp_reas_set.add(3)
                if inn_column_name=="br_ver" and true_elem != aim_elem: #проверка версии браузера
                    if 3 not in temp_reas_set: #если браузер отличается, сверять версии нет смысла
                        if 1 in temp_reas_set: #согласно предположению невозможна одновременная смена ОС и версии браузера, однако смена версии ОС и версии браузера допустима
                            temp_reas_set.clear()
                            break
                        else:
                            temp_reas_set.add(4)                                
                if inn_column_name=="br_ver":
                    if len(temp_reas_set)==0: #на случай полного совпадения кроме device_id
                        temp_reas_set.add(5)
                    r_id=calc_helper(df_2,aim_index,true_index,r_id)
                    reas_set=reas_set.union(temp_reas_set)
                    #print("Y", temp_reas_set) #оставляю в коде для облегчения проверки логики программы(2)
                    temp_reas_set.clear()
            #print(true_index, aim_index) #оставляю в коде для облегчения проверки логики программы(3) 
        if len(reas_set)==0 and df_2.at[true_index, "rdev_id"]==None: #проставим уникальные идентификаторы для устройств без дубликатов (проверка с None на случай наличия дубля по device_id)
            df_2.at[true_index, "rdev_id"]=r_id
            r_id+=1
        else: #проставим предполагаемые причины неуникальности
            df_2.at[true_index, "reason"]=set() #по неизвестной причине передача множества reas_set напрямую приводила к образованию пустого множества (предположительно из-за NoneType элемента)
            df_2.at[true_index, "reason"].update(reas_set)
print("Результат внутренней проверки: обнаружено " + str(len(pd.unique(df_2[["rdev_id"]].values.ravel('K')))) + " потенциально реальных устройств")


# In[9]:


df_3=df_2 #упорядочиваем полученные данные в новой таблице
df_3=df_3.iloc[:, [0,1,7,8]] #удалим лишние столбцы. В связи с тем, что столбец reason состоит из множеств, удалим дубли после его очистки
un_devs = pd.unique(df_3[["device_id"]].values.ravel('K')) #формируем массив уникальных идентификаторов устройств
for un_dev in un_devs: #устроим внешнюю проверку (между логинами по идентификатору устройства)
    outer_check = df_3.loc[find_mask(df_3,"device_id",un_dev)]
    outer_counter = 0
    for aim_index in outer_check.index: #проверяем, чтобы у одного идентификатора устройства не было нескольких rdev_id
        if outer_counter==0:
            true_index=aim_index
        else:
            if df_3.at[aim_index, "rdev_id"] != df_3.at[true_index, "rdev_id"]:
                r_id=calc_helper(df_3, aim_index, true_index, r_id)
        outer_counter+=1
un_rdevs = pd.unique(df_3[["rdev_id"]].values.ravel('K')) #формируем массив уникальных реальных идентификаторов устройств
group_count=0
for un_rdev in un_rdevs: #объединяем множества причин для каждого реалиного идентификатора устройства
    outer_check_2 = df_3.loc[find_mask(df_3,"rdev_id",un_rdev)]
    reas_set.clear()
    reas_statement = ""
    group_count+=1
    group_name = "r_dev_" + str(group_count)
    for aim_index in outer_check_2.index:
        curr_reas = df_3.at[aim_index, "reason"]
        if curr_reas == None:
            curr_reas=set()
        reas_set=reas_set.union(curr_reas)
    for n in range(len(reas_set)):
        reas = reas_set.pop()
        reas_statement += str(reasons[reas]) + ", " #переведём причины на русский язык
    for aim_index in outer_check_2.index: #и вставим их в текст, а также обновим названия
        if len(reas_statement)==0:
            reas_statement="уникальный  "
        df_3.at[aim_index, "reason"] = reas_statement[:-2]
        df_3.at[aim_index, "rdev_id"] = group_name
print("Результат внешней проверки: обнаружено " + str(group_count) + " реальных устройств(а)")


# In[12]:


df_Task2,df_Task3=df_3,df_3
df_Task2=df_Task2.iloc[:, [0,2,3]].drop_duplicates().reset_index(drop=True) #убираем лишние строки и столбец логинов, чтобы получить ответ на второе задание
df_Task3=df_Task3.iloc[:, [1,2]].drop_duplicates().reset_index(drop=True) #проводим ту же операцию для получения ответа на третье задание
print("Таблица по результатам задания 2")
print(df_Task2)
print("Таблица по результатам задания 3")
print(df_Task3)
print("Подготовка общего графа (розовым отмечены люди, серым - реальные устройства):")
graph_df=df_Task3 #сформируем таблицу для визуализации
for i in range(len(graph_df)): #уменьшим логин до первых 8 символов
    graph_df.at[i, "login"]=graph_df.at[i, "login"][:8]
g=nx.from_pandas_edgelist(graph_df, "rdev_id", "login") #создадим общий график
node_size_list=[]
for node in g.nodes():
    if node[:2]=="r_":
        node_size_list.append(100)
    else:
        node_size_list.append(10)
nx.draw_kamada_kawai(g, cmap=plt.cm.Pastel1, node_size=node_size_list, node_color=node_size_list, font_weight="bold")
plt.show()
print("Граф по случайному реальному устройству (логин сокращён до восьми символов):")
make_a_random_graph(graph_df, "rdev_id", "login")
plt.show()
print("Граф по случайному логину (логин сокращён до восьми символов):")
make_a_random_graph(graph_df, "login", "rdev_id")
plt.show()


# In[ ]:




