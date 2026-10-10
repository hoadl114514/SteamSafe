from pathlib import Path
from PIL import Image, ImageDraw
root = Path(__file__).parents[1]
im = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
draw = ImageDraw.Draw(im)
draw.rounded_rectangle((8, 8, 248, 248), radius=64, fill="#121c26")
draw.polygon([(128, 42), (198, 67), (188, 151), (164, 188), (128, 213), (92, 188), (68, 151), (58, 67)], fill="#42d8bd")
draw.line([(92, 127), (117, 150), (164, 97)], fill="#121c26", width=18, joint="curve")
im.save(root / "assets/app.ico", sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
