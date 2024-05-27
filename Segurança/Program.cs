using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Segurança
{
    internal class Program
    {
        static void Main(string[] args)
        {
            WindowsIdentity identity = ExibeInfoIdentity();
            WindowsPrincipal principal = ExibeInfoPrincipal(identity);
            ExibeInfoClaims(principal.Claims);
            Console.ReadLine();
        }


        public static WindowsIdentity ExibeInfoIdentity()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (identity == null)
            {
                Console.WriteLine("Não é um Windows Identity");
                return null;
            }
            Console.WriteLine($"Tipo de Identity : {identity}");
                Console.WriteLine("R: Esta linha indica o tipo de identidade do usuário do Windows.");
            Console.WriteLine($"Nome : {identity.Name}");
                Console.WriteLine("R: Aqui está o nome do usuário autenticado");
            Console.WriteLine($"Autenticado : {identity.IsAuthenticated}");
                Console.WriteLine("R: Indica se o usuário está autenticado ou não.");
            Console.WriteLine($"Tipo de Autenticação : {identity.AuthenticationType}");
                Console.WriteLine("R: Kerberos é um protocolo de autenticação usado para verificar a identidade de um usuário ou host.");
            Console.WriteLine($"É usuário Anônimo ? : {identity.IsAnonymous}");
                Console.WriteLine("R: Indica se o usuário é anônimo ou não.");
            Console.WriteLine($"Token de acesso : " + $"{identity.AccessToken.DangerousGetHandle()}");
                Console.WriteLine("R: O token de acesso atribuído ao usuário. Um token de acesso é um objeto de segurança que é utilizado para comprovar a identidade de um usuário e conceder acesso a recursos específicos em um sistema de computador ou rede.");
            Console.WriteLine();
            return identity;
        }


        public static WindowsPrincipal ExibeInfoPrincipal(WindowsIdentity identity)
        {
            Console.WriteLine("Informação do Principal");
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            if (principal == null)
            {
                Console.WriteLine("Não é um Windows Principal");
                return null;
            }
            Console.WriteLine($"É Usuário ? {principal.IsInRole(WindowsBuiltInRole.User)}");
                Console.WriteLine("R: Indica se o principal é um usuário.");
            Console.WriteLine($"É Administrador ? {principal.IsInRole(WindowsBuiltInRole.Administrator)}");
                Console.WriteLine("R: Indica se o principal é um administrador do sistema.");
            Console.WriteLine();
            return principal;
        }


        public static void ExibeInfoClaims(IEnumerable<Claim> claims)
        {
            Console.WriteLine("Declarações (Claims) ");
                Console.WriteLine("R: ");
            foreach (var claim in claims)
            {
                Console.WriteLine($"Assunto : {claim.Subject}");
                Console.WriteLine($"Emissor : {claim.Issuer}");
                Console.WriteLine($"Tipo : {claim.Type}");
                Console.WriteLine($"Valor do Tipo : {claim.ValueType}");
                Console.WriteLine($"Valor : {claim.Value}");
                foreach (var prop in claim.Properties)
                {
                    Console.WriteLine($"\tProperty: {prop.Key} {prop.Value}");
                }
                Console.WriteLine();
            }
        }


    }
}
