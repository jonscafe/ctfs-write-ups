from PIL import Image
import wave
import struct

def png_to_wav(input_png, output_wav):
    image = Image.open(input_png)
    
    pixel_data = list(image.getdata())
    
    num_channels = 1  
    sample_width = 2  
    framerate = 44100  
    num_frames = len(pixel_data)  

    with wave.open(output_wav, 'w') as wav_file:
        wav_file.setparams((num_channels, sample_width, framerate, num_frames, 'NONE', 'not compressed'))

        for pixel_value in pixel_data:
            audio_sample = int((pixel_value[0] / 255.0) * 65535.0) - 32768
            wav_file.writeframes(struct.pack('<h', audio_sample))

    print(f"PNG image '{input_png}' converted to WAV audio '{output_wav}' successfully.")

if __name__ == "__main__":
    input_png = "wavs.png" 
    output_wav = "output1.wav"
    
    png_to_wav(input_png, output_wav)


