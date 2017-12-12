import functions as g

def run():
    default_file = "files/annechatte.png"
    #filename = g.chooseFilename("Choose file to encrypt", default_file)
    filename = default_file

    print("File to encrypt : ", filename)

    with open(filename, "rb") as f:
        print("File content:")
        chunks = g.chunk_file(f)
        string = []
        for bytes in chunks:
            for byte in bytes:
                string.append(byte)

        print(string)

        print("#")

        #...