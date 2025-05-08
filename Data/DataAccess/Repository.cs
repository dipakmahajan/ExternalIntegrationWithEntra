using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace Data.DataAccess
{
    public interface IRepository<TEntity> where TEntity : class
    {
        TEntity Add(TEntity entity);

        void AddRange(IEnumerable<TEntity> entities);

        Task<TEntity> AddAsync(TEntity entity);

        TEntity Get(int id);

        IEnumerable<TEntity> GetAll();

        Task<List<TEntity>> GetAllAsync();

        IEnumerable<TEntity> Find(Expression<Func<TEntity, bool>> predicate);

        Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate);

        void Remove(TEntity entity);

        void RemoveRange(IEnumerable<TEntity> entites);

        Task RemoveAsync(TEntity entity);

        Task RemoveRangeAsync(IEnumerable<TEntity> entites);

        void Update(TEntity entity);

        Task<TEntity> UpdateAsync(TEntity entity);

        void UpdateVoidAsync(TEntity entity);
    }

    public class Repository<TEntity> : IRepository<TEntity> where TEntity : class
    {
        protected readonly ApplicationDbContext Context;
        public Repository(ApplicationDbContext dbcontext)
        {
            Context = dbcontext;
        }


        public TEntity Get(int id)
        {
            return Context.Set<TEntity>().Find(id);
        }

        public IEnumerable<TEntity> GetAll()
        {
            return Context.Set<TEntity>().ToList();
        }

        public IEnumerable<TEntity> Find(Expression<Func<TEntity, bool>> predicate)
        {
            return Context.Set<TEntity>().Where(predicate);
        }

        public TEntity Add(TEntity entity)
        {
            Context.Set<TEntity>().Add(entity);
            Context.SaveChanges();
            return entity;
        }

        public void AddRange(IEnumerable<TEntity> entities)
        {
            Context.Set<TEntity>().AddRange(entities);
            Context.SaveChanges();
        }

        public void Remove(TEntity entity)
        {
            Context.Set<TEntity>().Remove(entity);
            Context.SaveChanges();
        }

        public void RemoveRange(IEnumerable<TEntity> entites)
        {
            Context.Set<TEntity>().RemoveRange(entites);
            Context.SaveChanges();

        }

        public void Update(TEntity entity)
        {
            Context.Set<TEntity>().Update(entity);
            Context.SaveChanges();
        }

        public Task<List<TEntity>> GetAllAsync()
        {
            return Context.Set<TEntity>().ToListAsync();
        }

        public async Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate)
        {
            return await Context.Set<TEntity>().Where(predicate).ToListAsync();
        }

        public async Task<TEntity> AddAsync(TEntity entity)
        {
            await Context.Set<TEntity>().AddAsync(entity);
            await Context.SaveChangesAsync();
            return entity;

        }
        public async Task RemoveAsync(TEntity entity)
        {
            Context.Set<TEntity>().Remove(entity);
            await Context.SaveChangesAsync();

        }

        public async Task RemoveRangeAsync(IEnumerable<TEntity> entites)
        {

            Context.Set<TEntity>().RemoveRange(entites);
            await Context.SaveChangesAsync();
        }

        public async Task<TEntity> UpdateAsync(TEntity entity)
        {           
            Context.Set<TEntity>().Update(entity);
            await Context.SaveChangesAsync();
            return entity;

        }

        public void UpdateVoidAsync(TEntity entity)
        {
            Context.Set<TEntity>().Update(entity);
            Context.SaveChangesAsync();
        }
    }


}
