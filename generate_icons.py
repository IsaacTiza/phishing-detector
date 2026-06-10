"""
Generate extension icons.
"""

from PIL import Image, ImageDraw
import os

def create_shield_icon(size):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([0, 0, size-1, size-1], fill=(15, 17, 23, 255))
    s = size
    shield = [
        (s*0.5,  s*0.08),
        (s*0.92, s*0.25),
        (s*0.92, s*0.55),
        (s*0.5,  s*0.92),
        (s*0.08, s*0.55),
        (s*0.08, s*0.25),
    ]
    draw.polygon(shield, fill=(30, 58, 95, 255))
    draw.polygon(shield, outline=(74, 158, 255, 255))
    if size >= 48:
        cx, cy = s*0.5, s*0.52
        lw = max(2, size//16)
        draw.line([cx-s*0.18, cy, cx-s*0.02, cy+s*0.18],
                  fill=(74, 255, 158, 255), width=lw)
        draw.line([cx-s*0.02, cy+s*0.18, cx+s*0.22, cy-s*0.18],
                  fill=(74, 255, 158, 255), width=lw)
    return img

os.makedirs(os.path.join("extension", "icons"), exist_ok=True)

for size in [16, 48, 128]:
    icon = create_shield_icon(size)
    path = os.path.join("extension", "icons", f"icon{size}.png")
    icon.save(path)
    print(f"Created icon{size}.png")

print("Icons generated successfully")