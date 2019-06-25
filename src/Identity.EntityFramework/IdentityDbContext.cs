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
        public IdentityDbContext() : this("DefaultConnection")
        {
        }

        public IdentityDbContext(string nameOrConnectionString) : base(nameOrConnectionString)
        {
        }

        public IdentityDbContext(DbConnection existingConnection, DbCompiledModel model, bool contextOwnsConnection) : base(existingConnection, model, contextOwnsConnection)
        {
        }

        public IdentityDbContext(DbCompiledModel model) : base(model)
        {
        }

        public IdentityDbContext(DbConnection existingConnection, bool contextOwnsConnection) : base(existingConnection, contextOwnsConnection)
        {
        }

        public IdentityDbContext(string nameOrConnectionString, DbCompiledModel model) : base(nameOrConnectionString, model)
        {
        }
    }

    public class IdentityDbContext<TUser> : IdentityDbContext<TUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim> where TUser : IdentityUser
    {
        public IdentityDbContext() : this("DefaultConnection")
        {
        }

        public IdentityDbContext(string nameOrConnectionString) : this(nameOrConnectionString, true)
        {
        }

        public IdentityDbContext(string nameOrConnectionString, bool throwIfV1Schema) : base(nameOrConnectionString)
        {
            if (throwIfV1Schema && IsIdentityV1Schema(this))
            {
                throw new InvalidOperationException(IdentityResources.IdentityV1SchemaError);
            }
        }

        public IdentityDbContext(DbConnection existingConnection, DbCompiledModel model, bool contextOwnsConnection) : base(existingConnection, model, contextOwnsConnection)
        {
        }

        public IdentityDbContext(DbCompiledModel model) : base(model)
        {
        }

        public IdentityDbContext(DbConnection existingConnection, bool contextOwnsConnection) : base(existingConnection, contextOwnsConnection)
        {
        }

        public IdentityDbContext(string nameOrConnectionString, DbCompiledModel model) : base(nameOrConnectionString, model)
        {
        }

        internal static bool IsIdentityV1Schema(DbContext db)
        {
            if (!(db.Database.Connection is SqlConnection sqlConnection))
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
            return Enumerable.All(columns, list2.Contains);
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

        public IdentityDbContext() : this("DefaultConnection")
        {
        }

        public IdentityDbContext(string nameOrConnectionString) : base(nameOrConnectionString)
        {
        }

        public IdentityDbContext(DbConnection existingConnection, DbCompiledModel model, bool contextOwnsConnection) : base(existingConnection, model, contextOwnsConnection)
        {
        }

        public IdentityDbContext(DbCompiledModel model) : base(model)
        {
        }

        public IdentityDbContext(DbConnection existingConnection, bool contextOwnsConnection) : base(existingConnection, contextOwnsConnection)
        {
        }

        public IdentityDbContext(string nameOrConnectionString, DbCompiledModel model) : base(nameOrConnectionString, model)
        {
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            if (modelBuilder == null)
            {
                throw new ArgumentNullException("modelBuilder");
            }
            EntityTypeConfiguration<TUser> entityTypeConfiguration = modelBuilder.Entity<TUser>().ToTable("Users");
            entityTypeConfiguration.HasMany(u => u.Roles).WithRequired().HasForeignKey(ur => ur.UserId);
            entityTypeConfiguration.HasMany(u => u.Claims).WithRequired().HasForeignKey((uc) => uc.UserId);
            entityTypeConfiguration.HasMany(u => u.Logins).WithRequired().HasForeignKey((ul) => ul.UserId);
            entityTypeConfiguration.Property(u => u.UserName).IsRequired().HasMaxLength(256)
                .HasColumnAnnotation("Index", new IndexAnnotation(new IndexAttribute("UserNameIndex")
                {
                    IsUnique = true
                }));
            entityTypeConfiguration.Property(u => u.Email).HasMaxLength(256);
            modelBuilder.Entity<TUserRole>().HasKey(r => new
            {
                r.UserId,
                r.RoleId
            }).ToTable("UserRoles");
            modelBuilder.Entity<TUserLogin>().HasKey((l) => new
            {
                l.LoginProvider,
                l.ProviderKey,
                l.UserId
            }).ToTable("UserLogins");
            modelBuilder.Entity<TUserClaim>().ToTable("UserClaims");
            EntityTypeConfiguration<TRole> entityTypeConfiguration2 = modelBuilder.Entity<TRole>().ToTable("Roles");
            entityTypeConfiguration2.Property(r => r.Name).IsRequired().HasMaxLength(256)
                .HasColumnAnnotation("Index", new IndexAnnotation(new IndexAttribute("RoleNameIndex")
                {
                    IsUnique = true
                }));
            entityTypeConfiguration2.HasMany(r => r.Users).WithRequired().HasForeignKey(ur => ur.RoleId);
        }

        protected override DbEntityValidationResult ValidateEntity(DbEntityEntry entityEntry, IDictionary<object, object> items)
        {
            if (entityEntry != null && entityEntry.State == EntityState.Added)
            {
                var list = new List<DbValidationError>();
                if (entityEntry.Entity is TUser user)
                {
                    if (Queryable.Any(Users, (u => string.Equals(u.UserName, user.UserName))))
                    {
                        list.Add(new DbValidationError("User", string.Format(CultureInfo.CurrentCulture, IdentityResources.DuplicateUserName, new object[1]
                        {
                            user.UserName
                        })));
                    }
                    if (RequireUniqueEmail && Queryable.Any(Users, (u => string.Equals(u.Email, user.Email))))
                    {
                        list.Add(new DbValidationError("User", string.Format(CultureInfo.CurrentCulture, IdentityResources.DuplicateEmail, new object[1]
                        {
                            user.Email
                        })));
                    }
                }
                else
                {
                    if (entityEntry.Entity is TRole role && Queryable.Any(Roles, (r => string.Equals(r.Name, role.Name))))
                    {
                        list.Add(new DbValidationError("Role", string.Format(CultureInfo.CurrentCulture, IdentityResources.RoleAlreadyExists, new object[1]
                        {
                            role.Name
                        })));
                    }
                }
                if (Enumerable.Any(list))
                {
                    return new DbEntityValidationResult(entityEntry, list);
                }
            }
            return base.ValidateEntity(entityEntry, items);
        }
    }
}