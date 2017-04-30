from tkinter import Frame, BOTH, X, Label, Entry, LEFT, RIGHT, E, N, Button, CENTER


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

        ############################################################################################

        frame_ver = Frame(frame_left)
        frame_ver.pack(fill=X)

        self.label_version = Label(frame_ver, text="Version:", width=LABEL_WIDTH, anchor=E)
        self.label_version.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_version = Entry(frame_ver)
        self.entry_version.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_operation = Frame(frame_left)
        frame_operation.pack(fill=X)

        self.label_operation = Label(frame_operation, text="Operation:", width=LABEL_WIDTH, anchor=E)
        self.label_operation.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_operation = Entry(frame_operation)
        self.entry_operation.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_privport = Frame(frame_left)
        frame_privport.pack(fill=X)

        self.label_privport = Label(frame_privport, text="Private port:", width=LABEL_WIDTH, anchor=E)
        self.label_privport.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_privport = Entry(frame_privport)
        self.entry_privport.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_pubport = Frame(frame_left)
        frame_pubport.pack(fill=X)

        self.label_pubport = Label(frame_pubport, text="Private port:", width=LABEL_WIDTH, anchor=E)
        self.label_pubport.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_pubport = Entry(frame_pubport)
        self.entry_pubport.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_lifetime = Frame(frame_left)
        frame_lifetime.pack(fill=X)

        self.label_lifetime = Label(frame_lifetime, text="Lifetime:", width=LABEL_WIDTH, anchor=E)
        self.label_lifetime.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_lifetime = Entry(frame_lifetime)
        self.entry_lifetime.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_ips = Frame(frame_left)
        frame_ips.pack(fill=X)

        self.label_ips = Label(frame_ips, text="Public IPs:", width=LABEL_WIDTH, anchor=E)
        self.label_ips.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_ips = Entry(frame_ips)
        self.entry_ips.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_gateway = Frame(frame_right)
        frame_gateway.pack(fill=X)

        self.label_gateway = Label(frame_gateway, text="Gateway:", width=LABEL_WIDTH, anchor=E)
        self.label_gateway.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_gateway = Entry(frame_gateway)
        self.entry_gateway.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_usetls = Frame(frame_right)
        frame_usetls.pack(fill=X)

        self.label_usetls = Label(frame_usetls, text="Use TLS:", width=LABEL_WIDTH, anchor=E)
        self.label_usetls.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_usetls = Entry(frame_usetls)
        self.entry_usetls.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_cert = Frame(frame_right)
        frame_cert.pack(fill=X)

        self.label_cert = Label(frame_cert, text="Client cert:", width=LABEL_WIDTH, anchor=E)
        self.label_cert.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_cert = Entry(frame_cert)
        self.entry_cert.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_key = Frame(frame_right)
        frame_key.pack(fill=X)

        self.label_key = Label(frame_key, text="Client key:", width=LABEL_WIDTH, anchor=E)
        self.label_key.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        self.entry_key = Entry(frame_key)
        self.entry_key.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_empty = Frame(frame_right)
        frame_empty.pack(fill=X)

        label_empty = Label(frame_empty, text="", width=LABEL_WIDTH, anchor=E)
        label_empty.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        ############################################################################################

        frame_button = Frame(frame_right)
        frame_button.pack(fill=X)

        self.button_send = Button(frame_button, text="Send", anchor=CENTER)
        self.button_send.pack(fill=X, padx=PADDING_AMOUNT)