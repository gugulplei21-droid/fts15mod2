import glob, re, sys
import xml.etree.ElementTree as ET

LIB = "modmenu"
NS = "{http://schemas.android.com/apk/res/android}"

root = ET.parse("out/AndroidManifest.xml").getroot()
pkg = root.get("package", "")

# Buscar la actividad que abre el juego (la del icono)
main = None
for act in root.iter("activity"):
    for f in act.iter("intent-filter"):
        cats = [c.get(NS + "name") for c in f.iter("category")]
        if "android.intent.category.LAUNCHER" in cats:
            main = act.get(NS + "name")
            break
    if main:
        break
if not main:
    sys.exit("No encontre la actividad principal")

if main.startswith("."):
    main = pkg + main
elif "." not in main:
    main = pkg + "." + main

rel = main.replace(".", "/") + ".smali"
files = glob.glob("out/smali*/" + rel)
if not files:
    sys.exit("No encontre el archivo " + rel)
path = files[0]
src = open(path, encoding="utf-8").read()

INJECT = ('    const-string v0, "%s"\n'
          '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n' % LIB)

# Si la clase ya tiene constructor estatico, lo parcheamos
m = re.search(r"\.method static constructor <clinit>\(\)V", src)
if m:
    start = m.start()
    end = src.find(".end method", start)
    body = src[start:end]
    loc = re.search(r"\.locals (\d+)\n", body)
    if not loc:
        sys.exit("El metodo usa .registers, avisame")
    n = max(int(loc.group(1)), 1)
    body = body[:loc.start()] + ".locals %d\n" % n + INJECT + body[loc.end():]
    src = src[:start] + body + src[end:]
else:
    # Si no existe, agregamos uno nuevo al final
    src += ("\n.method static constructor <clinit>()V\n"
            "    .locals 1\n" + INJECT +
            "    return-void\n.end method\n")

open(path, "w", encoding="utf-8").write(src)
print("Mod inyectado en", path)
