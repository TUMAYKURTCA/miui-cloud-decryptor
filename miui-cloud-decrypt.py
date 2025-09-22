import os
import filetype
from Crypto.Cipher import AES
from Crypto.Util import Counter
from typing import Union

sAesIv = 22696201676385068962342234041843478898
secretKey = b'0\x82\x04l0\x82\x03T\xa0\x03\x02\x01\x02\x02\t\x00'


# Added function: ensure decrypted files are stored in a dedicated "decrypted" folder
# This avoids mixing input and output files in the same directory.
def _ensure_output_dir(base_dir: str) -> str:
    base_dir = os.path.abspath(base_dir or ".")
    parent_dir = os.path.dirname(base_dir)
    out_dir = os.path.join(parent_dir, "decrypted")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


# Added function: generate unique output filenames to prevent overwriting
# If a file with the same name already exists, it appends a numeric suffix (_1, _2, etc.)
def _unique_outpath(path_no_ext: str, ext: str) -> str:
    ext = ext or 'unknown'
    candidate = f"{path_no_ext}.{ext}"
    if not os.path.exists(candidate):
        return candidate
    i = 1
    while True:
        candidate = f"{path_no_ext}_{i}.{ext}"
        if not os.path.exists(candidate):
            return candidate
        i += 1


def decrypt_file_header(filename: Union[str, os.PathLike]):
    with open(filename, 'rb') as file:
        size = os.path.getsize(filename)
        header_size = max(min(1024, size), 16)
        counter = Counter.new(128, initial_value=sAesIv)
        aes = AES.new(secretKey, mode=AES.MODE_CTR, counter=counter)
        return aes.decrypt(file.read(header_size)) + file.read(size - header_size)


def decrypt_file(filename: Union[str, os.PathLike]):
    with open(filename, 'rb') as file:
        counter = Counter.new(128, initial_value=sAesIv)
        aes = AES.new(secretKey, mode=AES.MODE_CTR, counter=counter)
        return aes.decrypt(file.read())


def main(path: Union[str, os.PathLike]):
    if os.path.isdir(path):
        for filename in os.listdir(path):
            filepath = os.path.join(path, filename)
            filename = filename.split('.')
            if filename[-1] == 'lsa':
                data = decrypt_file(filepath)
            elif filename[-1] == 'lsav':
                data = decrypt_file_header(filepath)
            else:
                continue
            ext = filetype.guess_extension(data[:1024]) or 'unknown'
            
            # Changed: instead of writing output in the same folder,
            # now results are placed inside the "decrypted" folder
            outdir = _ensure_output_dir(path)
            
            # Changed: prevents overwriting files by using _unique_outpath
            outpath = _unique_outpath(os.path.join(outdir, filename[0]), ext)
            
            with open(outpath, 'wb') as file:
                file.write(data)
                print(f'{".".join(filename)} has been decrypted successfully')
    else:
        basename = os.path.basename(path).split('.')
        dirname = os.path.dirname(path)
        if basename[-1] == 'lsa':
            data = decrypt_file(path)
        elif basename[-1] == 'lsav':
            data = decrypt_file_header(path)
        else:
            print('Provided file must be .lsa or .lsav')
            return
        ext = filetype.guess_extension(data[:1024]) or 'unknown'
        
        # Changed: output goes to "decrypted" directory instead of the same folder
        outdir = _ensure_output_dir(dirname)
        
        # Changed: unique output filename to avoid overwriting
        outpath = _unique_outpath(os.path.join(outdir, basename[0]), ext)
        
        with open(outpath, 'wb') as file:
            file.write(data)
        print(f'{".".join(basename)} has been decrypted successfully')


if __name__ == '__main__':
    import sys

    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        print(
            'Usage:\n\t'
            'python ./miui-cloud-decrypt.py <file .lsa or .lsav / directory of files>\n'
            'Example:\n\t'
            'python ./miui-cloud-decrypt.py ./01234.56789.lsa\n\t'
            'or\n\t'
            'python ./miui-cloud-decrypt.py ./MyLsavFiles'
        )
