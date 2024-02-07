from scipy.io import wavfile
import matplotlib.pyplot as plt

sample_rate, data = wavfile.read('./TSCCTF 2024/Misc/TL;DL/flag-tldl.wav')

left_channel = data[:, 0]
right_channel = data[:, 1]

plt.figure()
plt.plot(left_channel, right_channel)

# Add labels
plt.xlabel('x')
plt.ylabel('y')
plt.title('A simple plot')

plt.show()