using Microsoft.IdentityFramework;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Common;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Data.Entity.Infrastructure.Annotations;
using System.Data.Entity.ModelConfiguration;
using System.Data.Entity.Validation;
using System.Data.SqlClient;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;

namespace Microsoft.IdentityFramework
{
    public class IdentityDbContext : IdentityDbContext<IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
    {
        public IdentityDbContext()
            : this("DefaultConnection")
        {
        }

        public IdentityDbContext(string nameOrConnectionString)
            : base(nameOrConnectionString)
        {
        }

        public IdentityDbContext(DbConnection existingConnection, DbCompiledModel model, bool contextOwnsConnection)
            : base(existingConnection, model, contextOwnsConnection)
        {
        }

        public IdentityDbContext(DbCompiledModel model)
            : base(model)
        {
        }

        public IdentityDbContext(DbConnection existingConnection, bool contextOwnsConnection)
            : base(existingConnection, contextOwnsConnection)
        {
        }

        public IdentityDbContext(string nameOrConnectionString, DbCompiledModel model)
            : base(nameOrConnectionString, model)
        {
        }
    }

    public class IdentityDbContext<TUser> : IdentityDbContext<TUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim> where TUser : IdentityUser
    {
        public IdentityDbContext()
            : this("DefaultConnection")
        {
        }

        public IdentityDbContext(string nameOrConnectionString)
            : this(nameOrConnectionString, true)
        {
        }

        public IdentityDbContext(string nameOrConnectionString, bool throwIfV1Schema)
            : base(nameOrConnectionString)
        {
            if (throwIfV1Schema && IsIdentityV1Schema(this))
            {
                throw new InvalidOperationException(IdentityResources.IdentityV1SchemaError);
            }
        }

        public IdentityDbContext(DbConnection existingConnection, DbCompiledModel model, bool contextOwnsConnection)
            : base(existingConnection, model, contextOwnsConnection)
        {
        }

        public IdentityDbContext(DbCompiledModel model)
            : base(model)
        {
        }

        public IdentityDbContext(DbConnection existingConnection, bool contextOwnsConnection)
            : base(existingConnection, contextOwnsConnection)
        {
        }

        public IdentityDbContext(string nameOrConnectionString, DbCompiledModel model)
            : base(nameOrConnectionString, model)
        {
        }

        internal static bool IsIdentityV1Schema(DbContext db)
        {
            SqlConnection sqlConnection = db.Database.Connection as SqlConnection;
            if (sqlConnection == null)
            {
                return false;
            }
            if (db.Database.Exists())
            {
                using (SqlConnection sqlConnection2 = new SqlConnection(sqlConnection.ConnectionString))
                {
                    sqlConnection2.Open();
                    return VerifyColumns(sqlConnection2, "Users", "Id", "UserName", "PasswordHash", "SecurityStamp", "Discriminator") && VerifyColumns(sqlConnection2, "Roles", "Id", "Name") && VerifyColumns(sqlConnection2, "UserRoles", "UserId", "RoleId") && VerifyColumns(sqlConnection2, "UserClaims", "Id", "ClaimType", "ClaimValue", "User_Id") && VerifyColumns(sqlConnection2, "UserLogins", "UserId", "ProviderKey", "LoginProvider");
                }
            }
            return false;
        }

        internal static bool VerifyColumns(SqlConnection conn, string table, params string[] columns)
        {
            List<string> list = new List<string>();
            using (SqlCommand sqlCommand = new SqlCommand("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS where TABLE_NAME=@Table", conn))
            {
                sqlCommand.Parameters.Add(new SqlParameter("Table", table));
                using (SqlDataReader sqlDataReader = sqlCommand.ExecuteReader())
                {
                    while (sqlDataReader.Read())
                    {
                        list.Add(sqlDataReader.GetString(0));
                    }
                }
            }
            List<string> list2 = list;
            return Enumerable.All<string>((IEnumerable<string>)columns, (Func<string, bool>)list2.Contains);
        }
    }

    public class IdentityDbContext<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim> : DbContext where TUser : IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim> where TRole : IdentityRole<TKey, TUserRole> where TUserLogin : IdentityUserLogin<TKey> where TUserRole : IdentityUserRole<TKey> where TUserClaim : IdentityUserClaim<TKey>
    {
        public virtual IDbSet<TUser> Users
        {
            get;
            set;
        }

        public virtual IDbSet<TRole> Roles
        {
            get;
            set;
        }

        public bool RequireUniqueEmail
        {
            get;
            set;
        }

        public IdentityDbContext()
            : this("DefaultConnection")
        {
        }

        public IdentityDbContext(string nameOrConnectionString)
            : base(nameOrConnectionString)
        {
        }

        public IdentityDbContext(DbConnection existingConnection, DbCompiledModel model, bool contextOwnsConnection)
            : base(existingConnection, model, contextOwnsConnection)
        {
        }

        public IdentityDbContext(DbCompiledModel model)
            : base(model)
        {
        }

        public IdentityDbContext(DbConnection existingConnection, bool contextOwnsConnection)
            : base(existingConnection, contextOwnsConnection)
        {
        }

        public IdentityDbContext(string nameOrConnectionString, DbCompiledModel model)
            : base(nameOrConnectionString, model)
        {
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            if (modelBuilder == null)
            {
                throw new ArgumentNullException("modelBuilder");
            }
            EntityTypeConfiguration<TUser> entityTypeConfiguration = modelBuilder.Entity<TUser>().ToTable("Users");
            entityTypeConfiguration.HasMany((TUser u) => u.Roles).WithRequired().HasForeignKey((TUserRole ur) => ur.UserId);
            entityTypeConfiguration.HasMany((TUser u) => u.Claims).WithRequired().HasForeignKey((TUserClaim uc) => uc.UserId);
            entityTypeConfiguration.HasMany((TUser u) => u.Logins).WithRequired().HasForeignKey((TUserLogin ul) => ul.UserId);
            entityTypeConfiguration.Property((TUser u) => u.UserName).IsRequired().HasMaxLength(256)
                .HasColumnAnnotation("Index", new IndexAnnotation(new IndexAttribute("UserNameIndex")
                {
                    IsUnique = true
                }));
            entityTypeConfiguration.Property((TUser u) => u.Email).HasMaxLength(256);
            modelBuilder.Entity<TUserRole>().HasKey((TUserRole r) => new
            {
                r.UserId,
                r.RoleId
            }).ToTable("UserRoles");
            modelBuilder.Entity<TUserLogin>().HasKey((TUserLogin l) => new
            {
                l.LoginProvider,
                l.ProviderKey,
                l.UserId
            }).ToTable("UserLogins");
            modelBuilder.Entity<TUserClaim>().ToTable("UserClaims");
            EntityTypeConfiguration<TRole> entityTypeConfiguration2 = modelBuilder.Entity<TRole>().ToTable("Roles");
            entityTypeConfiguration2.Property((TRole r) => r.Name).IsRequired().HasMaxLength(256)
                .HasColumnAnnotation("Index", new IndexAnnotation(new IndexAttribute("RoleNameIndex")
                {
                    IsUnique = true
                }));
            entityTypeConfiguration2.HasMany((TRole r) => r.Users).WithRequired().HasForeignKey((TUserRole ur) => ur.RoleId);
        }

        protected override DbEntityValidationResult ValidateEntity(DbEntityEntry entityEntry, IDictionary<object, object> items)
        {
            if (entityEntry != null && entityEntry.State == EntityState.Added)
            {
                List<DbValidationError> list = new List<DbValidationError>();
                TUser user = entityEntry.Entity as TUser;
                if (user != null)
                {
                    if (Queryable.Any<TUser>((IQueryable<TUser>)Users, (Expression<Func<TUser, bool>>)((TUser u) => string.Equals(u.UserName, user.UserName))))
                    {
                        list.Add(new DbValidationError("User", string.Format(CultureInfo.CurrentCulture, IdentityResources.DuplicateUserName, new object[1]
                        {
                            user.UserName
                        })));
                    }
                    if (RequireUniqueEmail && Queryable.Any<TUser>((IQueryable<TUser>)Users, (Expression<Func<TUser, bool>>)((TUser u) => string.Equals(u.Email, user.Email))))
                    {
                        list.Add(new DbValidationError("User", string.Format(CultureInfo.CurrentCulture, IdentityResources.DuplicateEmail, new object[1]
                        {
                            user.Email
                        })));
                    }
                }
                else
                {
                    TRole role = entityEntry.Entity as TRole;
                    if (role != null && Queryable.Any<TRole>((IQueryable<TRole>)Roles, (Expression<Func<TRole, bool>>)((TRole r) => string.Equals(r.Name, role.Name))))
                    {
                        list.Add(new DbValidationError("Role", string.Format(CultureInfo.CurrentCulture, IdentityResources.RoleAlreadyExists, new object[1]
                        {
                            role.Name
                        })));
                    }
                }
                if (Enumerable.Any<DbValidationError>((IEnumerable<DbValidationError>)list))
                {
                    return new DbEntityValidationResult(entityEntry, list);
                }
            }
            return base.ValidateEntity(entityEntry, items);
        }
    }
}