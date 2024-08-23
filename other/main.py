import cv2
import mediapipe as mp
import numpy as np
from PIL import Image
#DO ALl the SHIT
imgCount = 941

blackScreen = Image.open("C:/Users/thetr/Documents/Python/PictureTime/3000x5000BlackScreen.png")

mp_face_mesh = mp.solutions.face_mesh
mp_drawing = mp.solutions.drawing_utils

while True:
    image = cv2.imread(f'D:/Pictures/Pictures/{imgCount}.png')
    try:
        image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    except:
        break
    
    with mp_face_mesh.FaceMesh(min_detection_confidence=0.5, min_tracking_confidence=0.5) as face_mesh:
        results = face_mesh.process(image_rgb)

        if results.multi_face_landmarks:
            for landmarks in results.multi_face_landmarks:
                leftEye = (int((landmarks.landmark[130].x * image.shape[1] + landmarks.landmark[243].x * image.shape[1]) / 2), int((landmarks.landmark[130].y * image.shape[0] + landmarks.landmark[243].y * image.shape[0]) / 2))
                rightEye = (int((landmarks.landmark[463].x * image.shape[1] + landmarks.landmark[359].x * image.shape[1]) / 2), int((landmarks.landmark[463].y * image.shape[0] + landmarks.landmark[359].y * image.shape[0]) / 2))

    if leftEye[1] > rightEye[1]:
        A = (rightEye[0], leftEye[1])
        direction = -1 
    else:
        A = (leftEye[0], rightEye[1])
    direction = 1 

    delta_x = rightEye[0] - leftEye[0]
    delta_y = rightEye[1] - leftEye[1]
    angle=np.arctan(delta_y/delta_x)
    angle = (angle * 180) / np.pi

    h, w = image.shape[:2]
    center = (w // 2, h // 2)
    M = cv2.getRotationMatrix2D(center, (angle), 1.0)
    rotated = cv2.warpAffine(image, M, (w, h))

    dist_1 = 455.0890022841686
    dist_2 = np.sqrt((delta_x * delta_x) + (delta_y * delta_y))
    ratio = dist_1 / dist_2

    h, w, c = image.shape
    dim = (int(w * ratio), int(h * ratio))
    resized = cv2.resize(rotated, dim)

    cv2.imwrite("C:/Users/thetr/Documents/Python/PictureTime/img.png", resized)
    image = cv2.imread("C:/Users/thetr/Documents/Python/PictureTime/img.png")
    image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    with mp_face_mesh.FaceMesh(min_detection_confidence=0.5, min_tracking_confidence=0.5) as face_mesh:
        results = face_mesh.process(image_rgb)

        if results.multi_face_landmarks:
            for landmarks in results.multi_face_landmarks:
                leftEye = (int((landmarks.landmark[130].x * image.shape[1] + landmarks.landmark[243].x * image.shape[1]) / 2), int((landmarks.landmark[130].y * image.shape[0] + landmarks.landmark[243].y * image.shape[0]) / 2))
                rightEye = (int((landmarks.landmark[463].x * image.shape[1] + landmarks.landmark[359].x * image.shape[1]) / 2), int((landmarks.landmark[463].y * image.shape[0] + landmarks.landmark[359].y * image.shape[0]) / 2))

    image = Image.open("C:/Users/thetr/Documents/Python/PictureTime/img.png")

    Image.Image.paste(blackScreen, image, (1200 - leftEye[0], 2500 - leftEye[1]))
    blackScreen.save(f"D:/Pictures/PictureTimeCompilation/{imgCount}.png")

    imgCount += 1

print(f"Program ended at imgCount = {imgCount}")