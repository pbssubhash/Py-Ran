```
.______   ____    ____      .______          ___      .__   __. 
|   _  \  \   \  /   /      |   _  \        /   \     |  \ |  | 
|  |_)  |  \   \/   / ______|  |_)  |      /  ^  \    |   \|  |
|   ___/    \_    _/ |______|      /      /  /_\  \   |  . `  | 
|  |          |  |          |  |\  \----./  _____  \  |  |\   | 
| _|          |__|          | _| `._____/__/     \__\ |__| \__|

PY-RAN is a ransomware simulator, built to assist Red/Blue teams test their defenses.

```
### USAGE
```
usage: py-ran.exe [-h] [--dir DIR] [--mode MODE] [--password PASSWORD]

optional arguments:
  -h, --help           show this help message and exit
  --dir DIR            Location of the Folder you want to simulate
  --mode MODE          Accepts encrypt or decrypt arguments.
  --password PASSWORD  Password to use for encryption/decryption.
```

### FAQ
#### Q. How do I run/execute it on my Windows machine?
A. Download the latest release: [Py-Ran Releases](https://github.com/pbssubhash/Py-Ran/releases/download/0.1/Py-Ran_Release_v0.1.zip); PASSWORD for the ZIP is `pyran`

#### Q. My AV/EDR did not detect the execution. What should I do? 
A. It means your environment is not ready to stop the tiny-est (not sure if that's a word, lol) ransomware threats. You have a lot of work to do. (First setup a backup mechanism!)

#### Q. My AV/EDR detected the execution. Does it mean I'm safe? 
A. Not really. Py-Ran is a very simple ransomware simulator. Watch this space for more details on possible precautions and steps against ransomwares.

### TO-DO
- [ ] Add some randomness and Configuration wizard.
- [ ] Beat EDRs at their own game!
- [ ] Write some references about precautions to be taken to avoid ransomware attacks

### DISCLAIMER
I'm not responsible for any mischief done using this tool. This tool is built purely for EDUCATIONAL Purposes.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
