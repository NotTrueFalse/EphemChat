def to_humain_readable(size:int)->str:
    for unit in ['Octets', 'Ko', 'Mo', 'Go', 'To']:
        if size < 1024.0:
            break
        size /= 1024.0
    return f"{size:.2f} {unit}"