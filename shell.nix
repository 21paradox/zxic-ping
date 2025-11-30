
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    atftp
  ];
  
  shellHook = ''
    echo "TFTP Server Environment"
    echo "Starting TFTP server on directory: $(pwd)/target/armv7-unknown-linux-musleabi/release"
    
    echo "TFTP root directory: $(pwd)/target/armv7-unknown-linux-musleabi/release"
    echo "Put your files in the tftp-root directory"
    echo "To start the server, run: atftpd --daemon --port 69 $(pwd)/target/armv7-unknown-linux-musleabi/release/"
    echo "To stop the server, find the process and kill it"

    echo "to pull file, at /etc_rw/ run: tftp -g -r zxic_ping 192.168.8.2 69"
  '';
}
