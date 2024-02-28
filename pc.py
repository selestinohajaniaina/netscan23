class PC:
    
    def __init__(self, operate_system):
        # operate_system est arg pour assigner l'objet os
        # os est objet import a l'instance
        self.operate_system = operate_system

    def prop(self, arg2 = True):
        """ cette methode retoune le propriete du machine qui utilise le serveur actuel """
        return self.operate_system.uname()

    def uid(self, arg2 = True):
        """ cette methode retourne l'identifiant de l'utilisateur du machine qui utilise le serveur actuel """
        return self.operate_system.geteuid()
    
    def user(self, arg2 = True):
        """ cette methode retoune le nom de l'utilisateur du machine qui utilise le serveur actuel """
        return self.operate_system.getlogin()

    def system(self, arg2 = True):
        """ cette methode retoune le nom du systeme """
        return self.operate_system.uname().sysname

    def bit(self, arg2 = True):
        """ cette methode retoune le version du bit du systeme """
        return self.operate_system.uname().machine

    def version(self, arg2 = True):
        """ cette methode retoune le version du systeme """
        return self.operate_system.uname().version

    def release(self, arg2 = True):
        """ cette methode retoune le release du systeme """
        return self.operate_system.uname().release

    def dist(self, arg2 = True):
        """ cette methode retoune le distribution du systeme """
        return self.operate_system.uname().nodename