def copy_doc(original_function):
    def wrapper(func):
        func.__doc__ = original_function.__doc__
        return func

    return wrapper
