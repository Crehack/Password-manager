import sys
from cli.main import cli_main
from gui.app import run_gui

def main():
    if len(sys.argv) > 1:  # Si arguments passés
        cli_main()
    else:  # Mode graphique par défaut
        run_gui()

if __name__ == "__main__":
    main()