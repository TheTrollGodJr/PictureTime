import subprocess as sp
import shlex
import cv2

# Video settings
width, height, n_frames, fps = 3000, 5000, 997, 10
outputName = "output.mp4"

# Create an FFmpeg process
cmd = f'ffmpeg -y -s {width}x{height} -pixel_format bgr24 -f rawvideo -r {fps} -i pipe: -c:v libx265 -pix_fmt yuv420p -crf 24 {outputName}'
process = sp.Popen(shlex.split(cmd), stdin=sp.PIPE)

# Load and write image frames
for i in range(n_frames):
    # Load your image frame using OpenCV or any other method
    frame = cv2.imread(f"D:/Pictures/PictureTimeCompilation/{i}.png")  # Adjust the file name and format
    
    # Check if the frame was successfully loaded
    if frame is not None:
        # Resize the frame to match the video dimensions if needed
        frame = cv2.resize(frame, (width, height))
        
        # Convert the frame to RGB color order
        #frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        
        # Write the frame to the FFmpeg process
        process.stdin.write(frame.tobytes())
    else:
        print(f"Failed to load frame {i}")

# Close stdin and wait for the process to finish
process.stdin.close()
process.wait()
process.terminate()