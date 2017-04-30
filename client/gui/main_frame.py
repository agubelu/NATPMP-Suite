from tkinter import Frame, BOTH, X, Label, Entry, LEFT, RIGHT, E, N, W, Button, CENTER, ttk, Checkbutton, NE, BOTTOM


LABEL_WIDTH = 10
PADDING_AMOUNT = 5


class MainFrame(Frame):

    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        self.init_gui()

    def init_gui(self):
        self.parent.title("NAT-PMP Client")
        self.pack(fill=BOTH, expand=True)

        frame_left = Frame(self)
        frame_left.pack(side=LEFT, anchor=N)

        frame_right = Frame(self)
        frame_right.pack(side=RIGHT, anchor=N)

        frame_send_button = Frame(self)
        frame_send_button.pack(side=BOTTOM, anchor=N)

        number_validator = self.register(is_number)
        number_dot_validator = self.register(number_or_dot)
        number_dot_comma_validator = self.register(number_or_dot_or_comma)

        ############################################################################################

        frame_ver = Frame(frame_left)
        frame_ver.pack(fill=X)

        self.label_version = Label(frame_ver, text="Version:", width=LABEL_WIDTH, anchor=E)
        self.label_version.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.select_version = ttk.Combobox(frame_ver, values=("NAT-PMP v0 (official)", "NAT-PMP v1 (custom)"))
        self.select_version.set("NAT-PMP v0 (official)")
        self.select_version.configure(state='readonly')
        self.select_version.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_operation = Frame(frame_left)
        frame_operation.pack(fill=X)

        self.label_operation = Label(frame_operation, text="Operation:", width=LABEL_WIDTH, anchor=E)
        self.label_operation.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.select_operation = ttk.Combobox(frame_operation, values=("NAT-PMP discovery", "TCP mapping", "UDP mapping"))
        self.select_operation.set("NAT-PMP discovery")
        self.select_operation.configure(state='readonly')
        self.select_operation.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_privport = Frame(frame_left)
        frame_privport.pack(fill=X)

        self.label_privport = Label(frame_privport, text="Private port:", width=LABEL_WIDTH, anchor=E)
        self.label_privport.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_privport = Entry(frame_privport, validate='all', validatecommand=(number_validator, '%P'))
        self.entry_privport.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_pubport = Frame(frame_left)
        frame_pubport.pack(fill=X)

        self.label_pubport = Label(frame_pubport, text="Private port:", width=LABEL_WIDTH, anchor=E)
        self.label_pubport.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_pubport = Entry(frame_pubport, validate='all', validatecommand=(number_validator, '%P'))
        self.entry_pubport.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_lifetime = Frame(frame_left)
        frame_lifetime.pack(fill=X)

        self.label_lifetime = Label(frame_lifetime, text="Lifetime:", width=LABEL_WIDTH, anchor=E)
        self.label_lifetime.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_lifetime = Entry(frame_lifetime, validate='all', validatecommand=(number_validator, '%P'))
        self.entry_lifetime.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_ips = Frame(frame_left)
        frame_ips.pack(fill=X)

        self.label_ips = Label(frame_ips, text="Public IPs:", width=LABEL_WIDTH, anchor=E)
        self.label_ips.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_ips = Entry(frame_ips, validate='all', validatecommand=(number_dot_comma_validator, '%P'))
        self.entry_ips.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_gateway = Frame(frame_right)
        frame_gateway.pack(fill=X)

        self.label_gateway = Label(frame_gateway, text="Gateway:", width=LABEL_WIDTH, anchor=E)
        self.label_gateway.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_gateway = Entry(frame_gateway, validate='all', validatecommand=(number_dot_validator, '%P'))
        self.entry_gateway.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_usetls = Frame(frame_right)
        frame_usetls.pack(fill=X)

        self.label_usetls = Label(frame_usetls, text="Use TLS:", width=LABEL_WIDTH, anchor=E)
        self.label_usetls.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.check_usetls = Checkbutton(frame_usetls, anchor=W)
        self.check_usetls.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_cert = Frame(frame_right)
        frame_cert.pack(fill=X)

        self.label_cert = Label(frame_cert, text="Client cert:", width=LABEL_WIDTH)
        self.label_cert.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT, anchor=NE)

        self.button_cert = Button(frame_cert, text="Select")
        self.button_cert.pack(padx=PADDING_AMOUNT, expand=False, anchor=W)
        self.text_cert = Label(frame_cert, text="No file selected")
        self.text_cert.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        ############################################################################################

        frame_key = Frame(frame_right)
        frame_key.pack(fill=X)

        self.label_key = Label(frame_key, text="Client key:", width=LABEL_WIDTH)
        self.label_key.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT, anchor=NE)

        self.button_key = Button(frame_key, text="Select")
        self.button_key.pack(padx=PADDING_AMOUNT, expand=False, anchor=W)
        self.text_key = Label(frame_key, text="No file selected")
        self.text_key.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        ############################################################################################

        frame_empty = Frame(frame_right)
        frame_empty.pack(fill=X)

        label_empty = Label(frame_empty, text="", width=LABEL_WIDTH, anchor=E)
        label_empty.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        ############################################################################################

        frame_button = Frame(frame_send_button)
        frame_button.pack(fill=X)

        self.button_send = Button(frame_send_button, text="Send", anchor=CENTER, height=2, width=10)
        self.button_send.pack(fill=X, padx=PADDING_AMOUNT)


############################################################################################
############################################################################################
############################################################################################

def is_number(text):
    try:
        int(text)
        return True
    except ValueError:
        return False


def number_or_dot(text):
    return all(is_number(x) or x == "." for x in text)


def number_or_dot_or_comma(text):
    return all(is_number(x) or x == "." or x == "," for x in text)