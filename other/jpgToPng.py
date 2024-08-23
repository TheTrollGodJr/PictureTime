from PIL import Image
import os
import datetime

files = os.listdir("D:/Pictures/other")
count = 941

#date = [2020, 7, 10] #The date to start at -- year, month, day
date = [2023, 7, 21]
currentDate = str(datetime.datetime.now()).split(" ")[0]
currentDate = [int(currentDate.split("-")[0]), int(currentDate.split("-")[1]), int(currentDate.split("-")[2])]

def dateChange(dateInput):
    global date
    year, month, day = dateInput
    day += 1

    if month == 2:
        if day > 29:
            day = 1
            month = 3
    
    elif (month == 1) or (month == 3) or (month == 5) or (month == 7) or (month == 8) or (month == 10) or (month == 12):
        if day > 31:
            day = 1
            if month == 12:
                year += 1
                month = 1
            else:
                month += 1
    
    else:
        if day > 30:
            day = 1
            month += 1
    
    date[0] = year
    date[1] = month
    date[2] = day

def dateToString(dateInput):
    year, month, day = dateInput
    year = str(year)

    if month < 10:
        month = "0" + str(month)
    else:
        month = str(month)
    
    if day < 10:
        day = "0" + str(day)
    else:
        day = str(day)

    return year + month + day

while True:
    for items in files:
        if dateToString(date) in items:
            #img = Image.open(f"E:/Photos/Picture Time/{items}")
            img = Image.open(f"D:/Pictures/other/{items}")
            if not "IMG" in items:
                if str(img.size[1]) == "1592":
                    img = img.rotate(90, expand=True)
                else:
                    img = img.rotate(-90, expand=True)
            img.save(f"D:/Pictures/Pictures/{count}.png")
            count += 1
            break
    dateChange(date)
    if (date[0] == currentDate[0]) and (date[1] == currentDate[1]) and (date[2] == currentDate[2]):
        break
