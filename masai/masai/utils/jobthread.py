import os
import inspect
import ctypes
import sys
from threading import Thread

class JobThread(Thread):
    '''
        JobThread class is the class that will handle the job from main class
    '''

    def __init__(self, parent=None, group=None, target=None, name=None, args=(), kwargs={}, daemon=None):
        self.parent = parent
        self._return = None
        self.activity_id = None
        # self._stop_event = threading.Event()
        super(JobThread, self).__init__(group=group, target=target, name=name, args=args, kwargs=kwargs, daemon=daemon)

    def run(self):
        print('Thread id %d (name: %s) start the job' % (self.ident, self.name))
        if self._target is not None:
            try:
                self._return = self._target(*self._args, **self._kwargs)
                if self._return is not None:
                    self._return.result['activityId'] = self.activity_id
                print('Thread id %d (name: %s) finish the job' % (self.ident, self.name))
            except KeyboardInterrupt:
                print('Thread was interrupted!!!')
        # Callback function
        if self.parent:
            print('Thread id %d (name: %s) notify %s (process id: %d)' % (self.ident, self.name, self.parent, os.getppid()))
            self.parent.callback(self, self._return)
    
    def terminate(self):
        self._raise_exc(KeyboardInterrupt)

    def _raise_exc(self, exctype):
        if not inspect.isclass(exctype):
            raise TypeError('Only types can be raised (not instances')  
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(self.ident, ctypes.py_object(exctype))
        if res == 0:
            raise ValueError('invalid thread id')
        elif res != 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(self.ident, 0)
            raise SystemError("PyThreadState_SetAsyncExc failed")