from tkinter                 import Tk
from client.gui.main_frame   import MainFrame

import os
import tkinter

def init_gui():
    main = Tk()
    icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.gif")
    icon_img = tkinter.PhotoImage(file=icon_path)
    main.tk.call("wm", "iconphoto", main._w, icon_img)
    frame = MainFrame(main)
    main.mainloop()
