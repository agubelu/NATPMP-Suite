from tkinter import ttk, filedialog
from tkinter import *


LABEL_WIDTH = 10
PADDING_AMOUNT = 5

V0_TEXT = "NAT-PMP v0 (RFC 6886)"
V1_TEXT = "NAT-PMP v1 (custom)"

OP0_TEXT = "NAT-PMP discovery"
OP1_TEXT = "UDP mapping"
OP2_TEXT = "TCP mapping"


class MainFrame(Frame):

    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        self.init_gui()
        self.init_handlers()

    def init_gui(self):
        # Initialise the user interface layout

        self.parent.title("NAT-PMP Client")
        self.pack(fill=BOTH, expand=True)

        frame_top_controls = Frame(self)
        frame_top_controls.pack(side=TOP, anchor=N)

        frame_left = Frame(frame_top_controls)
        frame_left.pack(side=LEFT, anchor=N)

        frame_right = Frame(frame_top_controls)
        frame_right.pack(side=RIGHT, anchor=N)

        frame_send_button = Frame(self)
        frame_send_button.pack(side=BOTTOM, anchor=N)

        frame_info_text = Frame(self)
        frame_info_text.pack(side=BOTTOM, anchor=S, fill=BOTH, expand=TRUE)

        number_validator = self.register(is_number)
        number_dot_validator = self.register(number_or_dot)
        number_dot_comma_validator = self.register(number_or_dot_or_comma)

        ############################################################################################

        frame_ver = Frame(frame_left)
        frame_ver.pack(fill=X)

        self.label_version = Label(frame_ver, text="Version:", width=LABEL_WIDTH, anchor=E)
        self.label_version.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        var_select_version = StringVar()
        self.select_version = ttk.Combobox(frame_ver, values=(V0_TEXT, V1_TEXT), textvariable=var_select_version)
        self.select_version.var = var_select_version
        self.select_version.set(V0_TEXT)
        self.select_version.configure(state='readonly')
        self.select_version.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_operation = Frame(frame_left)
        frame_operation.pack(fill=X)

        self.label_operation = Label(frame_operation, text="Operation:", width=LABEL_WIDTH, anchor=E)
        self.label_operation.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        var_select_operation = StringVar()
        self.select_operation = ttk.Combobox(frame_operation, values=(OP0_TEXT, OP1_TEXT, OP2_TEXT), textvariable=var_select_operation)
        self.select_operation.var = var_select_operation
        self.select_operation.set(OP0_TEXT)
        self.select_operation.configure(state='readonly')
        self.select_operation.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_privport = Frame(frame_left)
        frame_privport.pack(fill=X)

        self.label_privport = Label(frame_privport, text="Private port:", width=LABEL_WIDTH, anchor=E)
        self.label_privport.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        var_private_port = StringVar()
        self.entry_privport = Entry(frame_privport, validate='all', validatecommand=(number_validator, '%P'), textvariable=var_private_port)
        self.entry_privport.var = var_private_port
        self.entry_privport.configure(state='readonly')
        self.entry_privport.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_pubport = Frame(frame_left)
        frame_pubport.pack(fill=X)

        self.label_pubport = Label(frame_pubport, text="Public port:", width=LABEL_WIDTH, anchor=E)
        self.label_pubport.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        var_public_port = StringVar()
        self.entry_pubport = Entry(frame_pubport, validate='all', validatecommand=(number_validator, '%P'), textvariable=var_public_port)
        self.entry_pubport.var = var_public_port
        self.entry_pubport.configure(state='readonly')
        self.entry_pubport.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_lifetime = Frame(frame_left)
        frame_lifetime.pack(fill=X)

        self.label_lifetime = Label(frame_lifetime, text="Lifetime:", width=LABEL_WIDTH, anchor=E)
        self.label_lifetime.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        var_lifetime = StringVar()
        self.entry_lifetime = Entry(frame_lifetime, validate='all', validatecommand=(number_validator, '%P'), textvariable=var_lifetime)
        self.entry_lifetime.var = var_lifetime
        self.entry_lifetime.configure(state='readonly')
        self.entry_lifetime.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_ips = Frame(frame_left)
        frame_ips.pack(fill=X)

        self.label_ips = Label(frame_ips, text="Public IPs:", width=LABEL_WIDTH, anchor=E)
        self.label_ips.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        var_ips = StringVar()
        self.entry_ips = Entry(frame_ips, validate='all', validatecommand=(number_dot_comma_validator, '%P'), textvariable=var_ips)
        self.entry_ips.var = var_ips
        self.entry_ips.configure(state='readonly')
        self.entry_ips.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_gateway = Frame(frame_right)
        frame_gateway.pack(fill=X)

        self.label_gateway = Label(frame_gateway, text="Gateway:", width=LABEL_WIDTH, anchor=E)
        self.label_gateway.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        var_gateway = StringVar(value="default")
        self.entry_gateway = Entry(frame_gateway, validate='all', validatecommand=(number_dot_validator, '%P'), textvariable=var_gateway, fg="#666666")
        self.entry_gateway.var = var_gateway
        self.entry_gateway.pack(fill=X, padx=PADDING_AMOUNT, expand=True)

        ############################################################################################

        frame_usetls = Frame(frame_right)
        frame_usetls.pack(fill=X)

        self.label_usetls = Label(frame_usetls, text="Use TLS:", width=LABEL_WIDTH, anchor=E)
        self.label_usetls.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        var_check_tls = IntVar()
        self.check_usetls = Checkbutton(frame_usetls, variable=var_check_tls, anchor=W)
        self.check_usetls.configure(state='disabled')
        self.check_usetls.var = var_check_tls
        self.check_usetls.pack(fill=X, padx=PADDING_AMOUNT, expand=True, anchor=W)

        ############################################################################################

        frame_cert = Frame(frame_right)
        frame_cert.pack(fill=X)

        self.label_cert = Label(frame_cert, text="Client cert:", width=LABEL_WIDTH)
        self.label_cert.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT, anchor=NE)

        self.button_cert = Button(frame_cert, text="Select")
        self.button_cert.configure(state='disabled')
        self.button_cert.pack(padx=PADDING_AMOUNT, expand=False, anchor=W)
        self.text_cert = Label(frame_cert, text="No file selected", justify=LEFT)
        self.text_cert.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT)

        ############################################################################################

        frame_key = Frame(frame_right)
        frame_key.pack(fill=X)

        self.label_key = Label(frame_key, text="Client key:", width=LABEL_WIDTH)
        self.label_key.pack(side=LEFT, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT, anchor=NE)

        self.button_key = Button(frame_key, text="Select")
        self.button_key.configure(state='disabled')
        self.button_key.pack(padx=PADDING_AMOUNT, expand=False, anchor=W)
        self.text_key = Label(frame_key, text="No file selected", justify=LEFT)
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

        frame_text = Frame(frame_info_text)
        frame_text.pack(fill=BOTH, expand=TRUE)

        scrollbar = ttk.Scrollbar(frame_text, orient=VERTICAL)

        self.info_text = Text(frame_text, height=11, padx=PADDING_AMOUNT, pady=PADDING_AMOUNT, yscrollcommand=scrollbar.set)
        self.info_text.insert(END, "Status: idle")

        scrollbar.config(command=self.info_text.yview)
        scrollbar.pack(fill=Y, side=RIGHT)

        self.info_text.configure(state=DISABLED)
        self.info_text.pack(fill=BOTH, padx=PADDING_AMOUNT, expand=TRUE)

    def init_handlers(self):
        # Initialise the various handlers

        # Handler for the "Use TLS" button, enables or disables the cert and key buttons
        def usetls_check_handler():
            if self.check_usetls.var.get():
                self.button_cert.configure(state='normal')
                self.button_key.configure(state='normal')
            else:
                self.button_cert.configure(state='disabled')
                self.button_key.configure(state='disabled')

        self.check_usetls.configure(command=usetls_check_handler)

        # Handler for the version and operation selectors, enables or disables the corresponding fields
        def version_operation_handler(_):
            v0 = self.select_version.var.get() == V0_TEXT
            info = self.select_operation.var.get() == OP0_TEXT

            if v0:
                self.check_usetls.var.set(0)
                self.check_usetls.configure(state="disabled")
                self.button_cert.configure(state='disabled')
                self.button_key.configure(state='disabled')
            else:
                self.check_usetls.configure(state="normal")

            if info:
                # Disable all entries, no matter the version
                self.entry_privport.configure(state="readonly")
                self.entry_pubport.configure(state="readonly")
                self.entry_lifetime.configure(state="readonly")
                self.entry_ips.configure(state="readonly")
            elif v0:
                # Request in v0, enable all but the public IPS field
                self.entry_privport.configure(state="normal")
                self.entry_pubport.configure(state="normal")
                self.entry_lifetime.configure(state="normal")
                self.entry_ips.configure(state="readonly")
            else:
                # Request in v1, enable all
                self.entry_privport.configure(state="normal")
                self.entry_pubport.configure(state="normal")
                self.entry_lifetime.configure(state="normal")
                self.entry_ips.configure(state="normal")

        self.select_version.bind("<<ComboboxSelected>>", version_operation_handler)
        self.select_operation.bind("<<ComboboxSelected>>", version_operation_handler)

        # Handlers for the placeholder text in the gateway entry
        def gateway_focusin_handler(_):
            if self.entry_gateway.var.get() == "default":
                self.entry_gateway.configure(fg="#000000")
                self.entry_gateway.var.set("")

        def gateway_focusout_handler(_):
            if self.entry_gateway.var.get() == "":
                self.entry_gateway.configure(fg="#666666")
                self.entry_gateway.var.set("default")

        self.entry_gateway.bind("<FocusIn>", gateway_focusin_handler)
        self.entry_gateway.bind("<FocusOut>", gateway_focusout_handler)

        # Handler for selecting files (client cert/key)
        def select_file_handler(button):
            file = filedialog.askopenfilename()
            text = ""
            n = 0

            for c in file:
                text += c
                n += 1
                if n >= 20 and (c == "/" or c == "\\"):
                    text += "\n"
                    n = 0

            if not text:
                text = "No file selected"

            if button == "cert":
                self.text_cert.configure(text=text)
            else:
                self.text_key.configure(text=text)

        self.button_cert.configure(command=lambda: select_file_handler("cert"))
        self.button_key.configure(command=lambda: select_file_handler("key"))

        # Finally, the handler for the Send button
        from client.gui.request_processor import process_request

        def send_button_handler():
            self.button_send.configure(state="disabled")
            process_request(self)
            self.button_send.configure(state="normal")

        self.button_send.configure(command=send_button_handler)


############################################################################################
############################################################################################
############################################################################################

    def reset_info_text(self):
        self.info_text.configure(state=NORMAL)
        self.info_text.delete(1.0, END)
        self.info_text.configure(state=DISABLED)
        self.parent.update_idletasks()

    def insert_info_line(self, text):
        self.info_text.configure(state=NORMAL)
        self.info_text.insert(END, text + "\n")
        self.info_text.see(END)
        self.info_text.configure(state=DISABLED)
        self.parent.update_idletasks()

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
