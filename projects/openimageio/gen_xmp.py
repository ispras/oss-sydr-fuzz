import os
from PIL import Image

def extract_xmp_from_image(file_path):
    with Image.open(file_path) as img:
        if "XML:com.adobe.xmp" in img.info:
            xmp_data = img.info["XML:com.adobe.xmp"]
            return xmp_data
        else:
            return None

for file in os.listdir('/corpus_png'):
    try:
        r = extract_xmp_from_image(os.path.join("/corpus_png", file))
        if r is not None:
            with open("/corpus_xmp/" + file + ".xmp", 'w') as f:
                f.write(r)
    except:
        pass
