import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

class PasswordChecker(tk.Tk):
    """Main application for Password Checker."""
    def __init__(self):
        """Initialize the PasswordChecker application."""
        super().__init__()
        self.title("PasswordChecker")
        self.geometry("430x600")
        self.resizable(False, False)
        self.pages = {}
        self.create_main_page()
        self.create_info_page()
        self.create_check_page()

    def create_main_page(self):
        """Create the main page."""
        main_page = tk.Frame(self, bg="lightblue")
        main_page.pack_propagate(False)
        main_page.pack(fill=tk.BOTH, expand=True)

        label = tk.Label(main_page, text="PasswordChecker", font=("Arial", 28), bg="lightblue")
        label.pack(pady=20)

        start_button = ttk.Button(main_page, text="Start", command=self.show_check_page, style="TButton")
        start_button.pack(pady=20, padx=20, ipadx=20, ipady=15)

        info_button = ttk.Button(main_page, text="Info", command=self.show_info_page, style="TButton")
        info_button.pack(pady=20, padx=20, ipadx=20, ipady=15)

        quit_button = ttk.Button(main_page, text="Quit", command=self.confirm_quit, style="TButton")
        quit_button.pack(pady=20, padx=20, ipadx=20, ipady=15)

        self.pages["main"] = main_page

    def create_info_page(self):
        """Create the info page."""
        info_page = tk.Frame(self, bg="lightgreen")
        info_page.pack_propagate(False)

        label = tk.Label(info_page, text="Info Page", font=("Arial", 28), bg="lightgreen")
        label.pack(pady=20)

        synopsis_label = tk.Label(info_page, text="Synopsis", font=("Arial", 18, "bold"), bg="lightgreen")
        synopsis_label.pack(pady=(0, 10), padx=20, anchor="w")

        synopsis_text = (
            "Password Checker is a simple application that assesses the strength of your passwords.\n\n"
            "It evaluates various factors such as length, use of uppercase and lowercase letters, symbols, numbers, "
            "and checks for common words to provide you with an estimation of your password's strength."
        )
        synopsis_content = tk.Label(info_page, text=synopsis_text, font=("Arial", 14), bg="lightgreen", wraplength=380, justify="left")
        synopsis_content.pack(padx=20, anchor="w")

        description_text = (
            #"This application is created using Python and the Tkinter library for the graphical user interface.\n\n"
            "Feel free to use it to check the strength of your passwords and receive recommendations on how to enhance them."
        )

        description_label = tk.Label(info_page, text="Description", font=("Arial", 18, "bold"), bg="lightgreen")
        description_label.pack(pady=10, padx=20, anchor="w")

        description_content = tk.Label(info_page, text=description_text, font=("Arial", 14), bg="lightgreen", wraplength=380, justify="left")
        description_content.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        back_button = ttk.Button(info_page, text="Back", command=self.show_main_page, style="TButton")
        back_button.pack(pady=20, ipadx=20, ipady=15)

        self.pages["info"] = info_page

    def create_check_page(self):
        """Create the check page."""
        check_page = tk.Frame(self, bg="lightyellow")
        check_page.pack_propagate(False)

        label = tk.Label(check_page, text="Password Checker Page", font=("Arial", 28), bg="lightyellow")
        label.pack(pady=2)

        # Entry widget for password input
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(check_page, font=("Arial", 18), width=20, show="*", textvariable=self.password_var)
        self.password_entry.pack(pady=2, padx=10, ipadx=10, ipady=10)  # Increased pady here

        # Button to show/hide the current password
        show_password_button = ttk.Button(check_page, text="Show Password", command=self.toggle_password, style="TButton")
        show_password_button.pack(pady=10, padx=10, ipadx=10, ipady=5)

        # Button to check the password strength
        check_button = ttk.Button(check_page, text="Check", command=self.check_strength, style="TButton")
        check_button.pack(pady=10, ipadx=20, ipady=10)  # Increased pady here

        # Label to display password strength result and recommendations
        self.result_label = tk.Label(check_page, text="", font=("Arial", 14), bg="lightyellow", wraplength=380, justify="left")
        self.result_label.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)  # Increased pady here

        # Button to go back to the main page
        back_button = ttk.Button(check_page, text="Back", command=self.show_main_page, style="TButton")
        back_button.pack(pady=20, ipadx=20, ipady=15)

        self.pages["check"] = check_page

    def show_page(self, page_name):
        """Show a specific page by hiding others."""
        for page in self.pages.values():
            page.pack_forget()
        self.pages[page_name].pack(fill=tk.BOTH, expand=True)

    def show_main_page(self):
        """Show the main page."""
        self.show_page("main")

    def show_info_page(self):
        """Show the info page."""
        self.show_page("info")

    def show_check_page(self):
        """Show the checker page."""
        self.show_page("check")

    def confirm_quit(self):
        """Confirm quitting the application."""
        result = messagebox.askquestion("Confirm Quit", "Are you sure you want to quit?")
        if result == "yes":
            self.destroy()

    def toggle_password(self):
        """Toggle between showing and hiding the password."""
        current_show_state = self.password_entry.cget("show")
        if current_show_state == "*":
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def check_strength(self):
        """Check the password strength and display the result."""
        password = self.password_var.get()
        # Validate if the password is empty
        if not password:
            self.result_label.config(text="No password entered. Please enter a password.")
            self.show_page("check")
            return

        strength, recommendations = self.calculate_strength(password)
        # Display the result on the check page with recommendations
        result_text = f"Password Strength: {strength}\n\n"
        if recommendations:
            result_text += "Recommendations to strengthen your password:\n"
            result_text += "\n".join(recommendations)
        self.result_label.config(text=result_text)
        self.show_page("check")

    def calculate_strength(self, password):
        """Calculate the password strength and provide recommendations."""
        weaknesses = []
        recommendations = set()

        length_requirement = 8
        lowercase_requirement = True
        uppercase_requirement = True
        symbol_requirement = True
        number_requirement = True
        common_words = ["password", "admin", "123456", "qwerty"]  # Add more common words as needed

        if len(password) < length_requirement:
            weaknesses.append("Password is too short.")
            recommendations.add(f"Use at least {length_requirement} characters.")

        if lowercase_requirement and not any(char.islower() for char in password):
            weaknesses.append("Include lowercase letters.")
            recommendations.add("Use a combination of uppercase and lowercase letters.")

        if uppercase_requirement and not any(char.isupper() for char in password):
            weaknesses.append("Include uppercase letters.")
            recommendations.add("Use a combination of uppercase and lowercase letters.")

        if symbol_requirement and not any(char in "! @ # $ % ^ & * ( ) _ + - = { } [ ] \ | ; : ' , < > . ? /…" for char in password):
            weaknesses.append("Include symbols (! @ # $ % ^ & * ( ) _ + - = { } [ ] \ | ; : ' , < > . ? /…).")
            recommendations.add("Use symbols to increase complexity.")

        if number_requirement and not any(char.isdigit() for char in password):
            weaknesses.append("Include numbers.")
            recommendations.add("Use numbers to increase complexity.")

        for common_word in common_words:
            if common_word.lower() in password.lower():
                weaknesses.append(f"Avoid using the common word '{common_word}' in your password.")
                recommendations.add(f"Avoid using '{common_word}' as part of your password.")

        # Provide recommendations based on identified weaknesses
        if len(weaknesses) > 0:
            recommendations_list = list(recommendations)
            recommendations_list.insert(0, "Consider the following to strengthen your password:")
            return 'Very Strong' if len(weaknesses) == 0 else 'Weak' if len(weaknesses) > 2 else 'Medium', recommendations_list

        return 'Very Strong', []

if __name__ == "__main__":
    app = PasswordChecker()
    app.mainloop()
