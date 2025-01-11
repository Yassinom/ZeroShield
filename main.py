import subprocess
import time

def run_in_new_tab(script_name):
    """
    Run a script in a new terminal tab using gnome-terminal.
    Args:
        script_name (str): The name of the script to run.
    """
    print(f"Starting {script_name} in a new terminal tab...")
    try:
        subprocess.Popen(["gnome-terminal", "--", "python3", script_name])
    except FileNotFoundError:
        print(f"Error: gnome-terminal is not installed or not available for {script_name}.")
    except Exception as e:
        print(f"An error occurred while starting {script_name}: {e}")

def main():
    """
    Main function to run all scripts in separate terminal tabs.
    """
    scripts = ["sniffer.py", "prediction.py", "gui.py", "zerodayprediction.py"]

    try:
        # Start each script in a new terminal tab
        for script in scripts:
            run_in_new_tab(script)
            time.sleep(2)  # Small delay for stability

        print("All scripts are running in separate terminal tabs.")
    
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

