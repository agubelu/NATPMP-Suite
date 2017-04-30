from tkinter                 import Tk
from client.gui.main_frame   import MainFrame


def init_gui():
    main = Tk()
    frame = MainFrame(main)
    main.mainloop()
