#v0.1.1
#@Chang Chen online 2025
#Write : Liu Yu chen
import cv2
import numpy as np

# 定义绿色的HSV范围（H: 0-180, S: 0-255, V: 0-255）
lower_green = np.array([35, 50, 50])  # 较低的HSV阈值
upper_green = np.array([85, 255, 255])  # 较高的HSV阈值

# 打开摄像头（0表示默认摄像头）
cap = cv2.VideoCapture(0)

while True:
    # 读取摄像头帧
    ret, frame = cap.read()
    if not ret:
        break

    # 将BGR转换为HSV颜色空间
    hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)

    # 创建绿色掩膜
    mask = cv2.inRange(hsv, lower_green, upper_green)

    # 形态学操作（去除噪声）
    kernel = np.ones((5, 5), np.uint8)
    mask = cv2.erode(mask, kernel, iterations=1)
    mask = cv2.dilate(mask, kernel, iterations=2)

    # 查找轮廓
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    # 检测绿色区域
    detected = False
    for cnt in contours:
        area = cv2.contourArea(cnt)
        if area > 500:  # 面积阈值，可根据实际情况调整
            detected = True
            break

    if detected:
        print(1)  # 检测到绿灯时打印1

    # 显示实时画面（可选）
    cv2.imshow('Frame', frame)
    cv2.imshow('Mask', mask)

    # 按q退出
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

# 释放资源
cap.release()
cv2.destroyAllWindows()