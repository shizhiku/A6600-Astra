# -*- coding: utf-8 -*-
"""渲染 9:16 竖屏视频叠加图层（透明 PNG 1080x1920）：
   - 顶部：大字标题（白 + 黑描边 + 阴影）
   - 底部：小号信息胶囊
   - 全局：上/下渐变压暗，压住模糊背景
"""
import sys
from PIL import Image, ImageDraw, ImageFont, ImageFilter

W, H = 1080, 1920
BOLD = r"C:\Windows\Fonts\msyhbd.ttc"   # 微软雅黑 Bold
REG = r"C:\Windows\Fonts\msyh.ttc"      # 微软雅黑 Regular

TITLE1 = "花费 1.000 元"
TITLE2 = "获得与神鲸对话的机会"
CAPTION = "DeepSeek-V4.1-Flash  ·  推理等级 Max"

OUT = sys.argv[1] if len(sys.argv) > 1 else "overlay.png"


def font(path, size):
    return ImageFont.truetype(path, size, index=0)


def centered(draw, text, fnt, y, *, fill, stroke_w=0, stroke_fill=None):
    box = draw.textbbox((0, 0), text, font=fnt, stroke_width=stroke_w)
    w = box[2] - box[0]
    draw.text(((W - w) // 2 - box[0], y - box[1]), text, font=fnt, fill=fill,
              stroke_width=stroke_w, stroke_fill=stroke_fill)


canvas = Image.new("RGBA", (W, H), (0, 0, 0, 0))

# 1) 上/下渐变压暗
grad = Image.new("RGBA", (W, H), (0, 0, 0, 0))
gd = ImageDraw.Draw(grad)
for y in range(0, 700):
    gd.line([(0, y), (W, y)], fill=(0, 0, 0, int(200 * (1 - y / 700) ** 1.5)))
for y in range(1240, H):
    gd.line([(0, y), (W, y)], fill=(0, 0, 0, int(165 * (y - 1240) / (H - 1240))))
canvas = Image.alpha_composite(canvas, grad)

# 2) 左下/右下小角标没有，保持干净

# 3) 主标题：先阴影
shadow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
sd = ImageDraw.Draw(shadow)
centered(sd, TITLE1, font(BOLD, 118), 132, fill=(0, 0, 0, 220))
centered(sd, TITLE2, font(BOLD, 94), 306, fill=(0, 0, 0, 220))
shadow = shadow.filter(ImageFilter.GaussianBlur(10))
canvas = Image.alpha_composite(canvas, shadow)

# 4) 主标题：白字 + 黑描边
text = Image.new("RGBA", (W, H), (0, 0, 0, 0))
td = ImageDraw.Draw(text)
centered(td, TITLE1, font(BOLD, 118), 132, fill=(255, 255, 255, 255),
         stroke_w=10, stroke_fill=(0, 0, 0, 255))
centered(td, TITLE2, font(BOLD, 94), 306, fill=(255, 236, 110, 255),
         stroke_w=8, stroke_fill=(0, 0, 0, 255))
canvas = Image.alpha_composite(canvas, text)

# 5) 底部信息胶囊
cap_font = font(REG, 46)
tmp = ImageDraw.Draw(Image.new("RGBA", (10, 10)))
cbox = tmp.textbbox((0, 0), CAPTION, font=cap_font)
cw, ch = cbox[2] - cbox[0], cbox[3] - cbox[1]
pad_x, pad_y = 44, 26
pill_w, pill_h = cw + pad_x * 2, ch + pad_y * 2
pill_x, pill_y = (W - pill_w) // 2, 1408
pill = Image.new("RGBA", (W, H), (0, 0, 0, 0))
pd = ImageDraw.Draw(pill)
pd.rounded_rectangle([pill_x, pill_y, pill_x + pill_w, pill_y + pill_h],
                     radius=pill_h // 2, fill=(255, 255, 255, 26),
                     outline=(255, 255, 255, 70), width=2)
pd.text((pill_x + pad_x - cbox[0], pill_y + pad_y - cbox[1]), CAPTION,
        font=cap_font, fill=(255, 255, 255, 232))
canvas = Image.alpha_composite(canvas, pill)

canvas.save(OUT, "PNG")
print(f"OK -> {OUT} {canvas.size}")
