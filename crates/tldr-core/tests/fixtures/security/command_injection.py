import os


def list_dir(request):
    filename = request.args.get("file")
    os.system("cat " + filename)
